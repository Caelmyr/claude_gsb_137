# -*- coding: utf-8 -*-
"""
quotas.py — 存储配额（用户级 / 目录级）
==========================================

核心原则：**用量口径与真实占用一致**。一个逻辑文件内容（以 content_hash
标识，块内容寻址天然去重）可能同时被三处引用：

  1. 活动文件树（meta['fs'] 的 root 子树）；
  2. 回收站（.trash 子树 + recycle 条目，块引用仍受 GC 保护）；
  3. 全部历史提交快照（meta['versions']，块不可变，历史版本永久可读）。

只按活动文件计费会产生两类怪象：
  * 删了文件（进回收站/被历史快照引用）实际没释放空间，配额却先放开口子
    => "明明超了还能继续写"；
  * 用户删了数据仍被判超限，只收到一句冷报错，不知道回收站/历史版本还
    占着空间 => 本模块在超限响应里直接给出**超了多少 + 占用构成 + 可清理
    项（回收站条目、仅历史引用的内容）**。

因此：
  * 用户配额用量 = 该用户在 活动 ∪ 回收站 ∪ 历史快照 中引用到的**去重后
    逻辑字节**（同一内容多处引用只计一份）；
  * 目录配额用量 = 该前缀下 活动 ∪ 历史快照 的去重逻辑字节。回收站已脱离
    原目录树，计入删除者的用户配额，不计回原目录（否则"删除"永远无法释放
    目录额度）；
  * 写拦截做两道：upload/begin 按声明大小预判定（分片都不接收），
    upload/complete 拿到真实内容哈希后在数据块落 DataNode 前做权威复核
    （覆盖同名文件、内容与历史去重等情况按集合精确计算）。
"""

import threading
import time

from . import config
from .util import gen_id, now, norm_path


class QuotaError(Exception):
    """通用配额配置错误。"""


class QuotaExceeded(Exception):
    """
    超限异常：携带结构化裁决结果，HTTP 层原样返回给前端，
    前端据此渲染"超了多少 / 占用构成 / 可清理项"。
    """

    def __init__(self, verdict):
        self.verdict = verdict
        scope = verdict.get("scope_label") or verdict.get("scope")
        super().__init__(verdict.get("message")
                         or f"存储配额超限：{scope}")


class QuotaManager:
    def __init__(self, nn):
        self.nn = nn
        self.meta = nn.meta
        self.lock = threading.RLock()
        self._collect_cache = None
        self._collect_ts = 0.0

    # ============================================================== 配置
    def _q(self):
        return self.meta.get("quotas")

    def ensure_seed(self):
        with self.meta.lock:
            q = self._q()
            q.setdefault("user", {})
            q.setdefault("dir", {})
            q.setdefault("default_user_limit", config.QUOTA_DEFAULT_USER_BYTES)
            q.setdefault("updated_at", now())
            self.meta.touch("quotas")

    def _user_entry(self, username):
        with self.meta.lock:
            return dict(self._q().get("user", {}).get(username) or {})

    def set_user_quota(self, username, limit_bytes, note="", actor="admin"):
        """设置用户配额；limit_bytes 为 0/None 表示取消限制。"""
        limit = self._normalize_limit(limit_bytes)
        with self.meta.lock:
            users = self.meta.get("users").get("users", {})
            if username not in users:
                raise QuotaError(f"用户不存在: {username}")
            doc = self._q()
            if limit is None:
                doc.get("user", {}).pop(username, None)
                action = "取消配额"
            else:
                doc.setdefault("user", {})[username] = {
                    "limit_bytes": limit,
                    "note": note or "",
                    "updated_at": now(),
                    "updated_by": actor,
                }
                action = f"设置配额 {limit} B"
            doc["updated_at"] = now()
            self.meta.touch("quotas")
        self.invalidate()
        self.nn.log_event("INFO", "quota", "user_set", username, actor, action)
        return {"ok": True, "username": username, "limit_bytes": limit}

    def set_dir_quota(self, path, limit_bytes, note="", actor="admin"):
        """设置目录配额（作用于该前缀及其全部子路径）。"""
        path = norm_path(path)
        limit = self._normalize_limit(limit_bytes)
        with self.meta.lock:
            if limit is None:
                self._q().get("dir", {}).pop(path, None)
                action = "取消目录配额"
            else:
                # 目录必须真实存在（避免把拼写错误的路径永久写成规则）
                inode = self.nn.fs.resolve(path, must_exist=False)
                if not inode or inode.get("type") != "dir":
                    raise QuotaError(f"目录不存在: {path}")
                self._q().setdefault("dir", {})[path] = {
                    "limit_bytes": limit,
                    "note": note or "",
                    "updated_at": now(),
                    "updated_by": actor,
                }
                action = f"设置目录配额 {limit} B"
            self._q()["updated_at"] = now()
            self.meta.touch("quotas")
        self.invalidate()
        self.nn.log_event("INFO", "quota", "dir_set", path, actor, action)
        return {"ok": True, "path": path, "limit_bytes": limit}

    @staticmethod
    def _normalize_limit(limit_bytes):
        if limit_bytes is None or limit_bytes == "":
            return None
        try:
            limit = int(limit_bytes)
        except (TypeError, ValueError):
            raise QuotaError("配额必须是整数字节数（0 表示不限）")
        if limit < 0:
            raise QuotaError("配额不能为负数")
        return limit or None  # 0 => 不限制

    def user_limit(self, username):
        """返回用户的有效配额（None = 不限）。"""
        with self.meta.lock:
            entry = self._q().get("user", {}).get(username)
            if entry and entry.get("limit_bytes"):
                return int(entry["limit_bytes"])
            default = self._q().get("default_user_limit", 0)
            return int(default) or None

    def dir_limits(self):
        with self.meta.lock:
            return {p: int(e.get("limit_bytes") or 0)
                    for p, e in self._q().get("dir", {}).items()
                    if e.get("limit_bytes")}

    # ============================================================== 计量
    # 计量结果短缓存：overview/me 这类只读接口可能被多个页面秒级轮询，
    # 而 _collect 要遍历全部提交快照；用 1.5s TTL 摊薄开销。
    # 写裁决（guard/evaluate）永远走实时 _collect，保证拦截权威。
    _COLLECT_TTL = 1.5

    def _collect(self, use_cache=False):
        if use_cache:
            with self.lock:
                age = time.time() - getattr(self, "_collect_ts", 0)
                if age < self._COLLECT_TTL and self._collect_cache is not None:
                    return self._collect_cache
        coll = self._collect_uncached()
        with self.lock:
            self._collect_cache = coll
            self._collect_ts = time.time()
        return coll

    def invalidate(self):
        with self.lock:
            self._collect_cache = None
            self._collect_ts = 0

    def _collect_uncached(self):
        nn = self.nn
        active_u, trash_u, hist_u = {}, {}, {}
        active_d, hist_d = {}, {}
        trash_items = []
        users = set()

        dir_prefixes = sorted(self.dir_limits().keys())

        def add(bucket, key, ch, size):
            if not ch:
                return
            bucket.setdefault(key, {})[ch] = int(size or 0)

        def dirs_for(path):
            # 命中的已配置配额目录（含自身与全部祖先前缀）
            hits = []
            for pfx in dir_prefixes:
                if path == pfx or path.startswith(pfx.rstrip("/") + "/"):
                    hits.append(pfx)
            return hits

        with self.meta.lock:
            # ---- 1. 活动文件树（walk 从 root 出发，天然不含 .trash）----
            for path, inode in nn.fs.walk_files():
                owner = inode.get("owner") or "anonymous"
                users.add(owner)
                ch, size = inode.get("content_hash"), inode.get("size", 0)
                add(active_u, owner, ch, size)
                for pfx in dirs_for(path):
                    add(active_d, pfx, ch, size)

            # ---- 2. 回收站：.trash 子树下的真实文件（哈希可精确去重）----
            # 归属规则：整个回收站条目（含目录子树）的占用计入**删除者**。
            # 删除时 inode 会打 _deleted_by 标记；旧数据缺标记时按顶层条目
            # 的 deleted_by 回退，保证字节归属与 recycle 条目、清理建议一致。
            trash_root = nn.fs.get_inode(nn.fs.trash_id)
            top_deleter = {}
            for it in nn.fs.recycle_list():
                top_deleter[it.get("inode")] = it.get("deleted_by")
                trash_items.append({
                    "id": it.get("id"),
                    "name": it.get("name"),
                    "type": it.get("type"),
                    "size": int(it.get("size", 0)),
                    "files": it.get("files", 1),
                    "owner": it.get("deleted_by") or "anonymous",
                    "original_path": it.get("original_path"),
                    "expires_at": it.get("expires_at"),
                })
            if trash_root:
                inodes = nn.fs._inodes()
                for top_id in list(trash_root.get("children", [])):
                    deleter = top_deleter.get(top_id)
                    stack = [top_id]
                    seen = set()
                    while stack:
                        cur = stack.pop()
                        if cur in seen:
                            continue
                        seen.add(cur)
                        node = inodes.get(cur)
                        if not node:
                            continue
                        if node.get("type") == "file":
                            owner = node.get("_deleted_by") or deleter \
                                or node.get("owner") or "anonymous"
                            users.add(owner)
                            add(trash_u, owner,
                                node.get("content_hash"),
                                node.get("size", 0))
                        else:
                            stack.extend(node.get("children", []))

            # ---- 3. 历史提交快照（全量；块不可变，受 GC 永久保护）----
            for commit in self.meta.get("versions").get("commits", {}).values():
                for path, e in commit.get("snapshot", {}).items():
                    ch = e.get("content_hash")
                    size = e.get("size", 0)
                    owner = e.get("owner") or "anonymous"
                    users.add(owner)
                    add(hist_u, owner, ch, size)
                    for pfx in dirs_for(path):
                        add(hist_d, pfx, ch, size)

        return {
            "active_u": active_u, "trash_u": trash_u, "hist_u": hist_u,
            "active_d": active_d, "hist_d": hist_d,
            "trash_items": trash_items, "users": sorted(users),
        }

    @staticmethod
    def _union_size(*maps):
        merged = {}
        for m in maps:
            for ch, size in (m or {}).items():
                merged[ch] = size
        return sum(merged.values()), merged

    def _scope_view(self, scope, key, coll, limit, extra=None):
        if scope == "user":
            a, t, h = (coll["active_u"].get(key, {}),
                       coll["trash_u"].get(key, {}),
                       coll["hist_u"].get(key, {}))
        else:
            a, t = coll["active_d"].get(key, {}), {}
            h = coll["hist_d"].get(key, {})
        b_active, _ = self._union_size(a)
        b_trash, _ = self._union_size(t)
        b_hist, _ = self._union_size(h)
        total, union = self._union_size(a, t, h)
        view = {
            "scope": scope,
            "scope_label": ("用户 " + key) if scope == "user"
                           else ("目录 " + key),
            "user" if scope == "user" else "path": key,
            "limit_bytes": limit,
            "used_bytes": total,
            "free_bytes": max(0, limit - total) if limit else None,
            "limited": bool(limit),
            "usage_ratio": round(total / limit, 4) if limit else 0.0,
            "breakdown": {
                "active": b_active,
                "trash": b_trash,
                "history": b_hist,
                "shared": b_active + b_trash + b_hist - total,  # 跨类别重复
            },
            "level": self._level(total, limit),
        }
        if extra:
            view.update(extra)
        return view

    @staticmethod
    def _level(used, limit):
        if not limit:
            return "unlimited"
        if used > limit:
            return "exceeded"
        if used >= limit * config.QUOTA_WARN_RATIO:
            return "warning"
        return "ok"

    # ---------------------------------------------------------- 公开视图
    def overview(self):
        """配额管理页：每个用户 + 每个目录的实时用量视图。"""
        with self.meta.lock:
            user_limits = {u: (e.get("limit_bytes") or 0)
                           for u, e in self._q().get("user", {}).items()}
            dir_cfg = {p: e for p, e in self._q().get("dir", {}).items()}
            default_limit = self._q().get("default_user_limit", 0)
        coll = self._collect(use_cache=True)

        # 全部真实用户（含尚未设配额的），管理员能逐个直接加配额
        all_users = []
        with self.meta.lock:
            for u in self.meta.get("users").get("users", {}).values():
                all_users.append(u["username"])
        for u in coll["users"]:
            if u not in all_users:
                all_users.append(u)

        user_views = []
        for username in sorted(set(all_users)):
            limit = int(user_limits.get(username) or 0) or None
            user_views.append(self._scope_view("user", username, coll, limit))
        dir_views = []
        for path, entry in sorted(dir_cfg.items()):
            limit = int(entry.get("limit_bytes") or 0) or None
            view = self._scope_view("dir", path, coll, limit)
            view["note"] = entry.get("note", "")
            view["updated_by"] = entry.get("updated_by", "")
            view["updated_at"] = entry.get("updated_at")
            dir_views.append(view)
        return {
            "users": user_views,
            "dirs": dir_views,
            "default_user_limit": int(default_limit or 0),
            "warn_ratio": config.QUOTA_WARN_RATIO,
            "counts": {
                "exceeded": sum(1 for v in user_views + dir_views
                                if v["level"] == "exceeded"),
                "warning": sum(1 for v in user_views + dir_views
                               if v["level"] == "warning"),
            },
        }

    def user_view(self, username, include_cleanup=True):
        """普通用户自查：用量 + 超限可清理建议。"""
        limit = self.user_limit(username)
        coll = self._collect()
        cleanup = self._cleanup_candidates(username, coll) if include_cleanup \
            else []
        view = self._scope_view("user", username, coll, limit,
                                {"cleanup": cleanup})
        return view

    def _cleanup_candidates(self, username, coll, limit_items=20):
        """
        给出该用户"能马上释放空间"的数据：
          * 回收站条目（彻底删除 / 清空即释放）；
          * 仅历史版本引用、活动树与回收站都已不存在的内容
            （只能随版本历史清理，给出占用量提示）。
        """
        items = []
        for it in coll["trash_items"]:
            if it.get("owner") == username:
                items.append({
                    "kind": "trash",
                    "id": it["id"], "name": it["name"],
                    "size": it["size"], "files": it.get("files", 1),
                    "original_path": it.get("original_path"),
                    "expires_at": it.get("expires_at"),
                    "action_hint": "彻底删除（或清空回收站）后立即计入释放",
                })
        items.sort(key=lambda x: -x["size"])

        # 仅历史版本引用的独有内容（活动/回收站都没有）
        active = coll["active_u"].get(username, {})
        trash = coll["trash_u"].get(username, {})
        history = coll["hist_u"].get(username, {})
        history_only = {ch: sz for ch, sz in history.items()
                        if ch not in active and ch not in trash}
        return {
            "trash_items": items[:limit_items],
            "trash_total": sum(i["size"] for i in items),
            "trash_more": max(0, len(items) - limit_items),
            "history_only_bytes": sum(history_only.values()),
            "history_only_items": len(history_only),
        }

    # ============================================================== 拦截
    def evaluate_write(self, username, target_path, new_size,
                       new_hash=None):
        """
        模拟"写入 target_path（覆盖/新建）"后，受影响的用户配额与目录配额
        的裁决。new_hash 未知（begin 阶段仅有声明大小）时按"全新内容"保守
        估算，宁可误拦；complete 阶段带真实哈希做精确复核。

        返回 {"allowed": bool, "checks": [scope_view...], "violations": [...]}
        """
        # begin 阶段（new_hash 未知）按"全新内容"保守估算，宁可误拦；
        # complete 阶段（new_hash 已知）为权威复核，精确处理覆盖与内容去重。
        coll = self._collect()
        target_path = norm_path(target_path)

        # 覆盖时旧 inode：owner 不变（create_file 保留原 owner），计费归属
        with self.meta.lock:
            old = self.nn.fs.resolve(target_path, must_exist=False)
        old = old if (old and old.get("type") == "file") else None
        owner = (old or {}).get("owner") or username
        old_hash = (old or {}).get("content_hash")
        old_size = (old or {}).get("size", 0)

        checks = []
        violations = []
        user_limit = self.user_limit(owner)
        checks.append(self._project("user", owner, coll, user_limit,
                                    old_hash, old_size, new_hash, new_size,
                                    scope_sets=("active_u", "trash_u", "hist_u")))

        # 目录：取目标路径命中的最深配额目录（最深者通常最紧）
        # —— 但所有祖先配额都必须满足，逐个检查
        for pfx, lim in self.dir_limits().items():
            if target_path == pfx or target_path.startswith(
                    pfx.rstrip("/") + "/"):
                checks.append(self._project(
                    "dir", pfx, coll, lim or None,
                    old_hash, old_size, new_hash, new_size,
                    scope_sets=("active_d", None, "hist_d")))

        allowed = all(c["projected_bytes"] <= c["limit_bytes"]
                      for c in checks if c["limit_bytes"])
        # begin 阶段（new_hash 未知）无法预判内容去重：只有当"本次写入大小
        # 本身就超过剩余额度"时才是确定性超限；否则放行建会话，由 complete
        # 用真实哈希做权威复核（可能因与历史/活动内容去重而实际不增占用）。
        tentative = new_hash is None
        for c in checks:
            if c["limit_bytes"] and c["projected_bytes"] > c["limit_bytes"]:
                # 不含本次写入的基线占用
                base_bytes = max(0, c["projected_bytes"]
                                 - int(new_size or 0))
                free = max(0, c["limit_bytes"] - base_bytes)
                definitive = int(new_size or 0) > free
                c["over_bytes"] = c["projected_bytes"] - c["limit_bytes"]
                c["tentative"] = tentative and not definitive
                c["message"] = self._violation_message(c)
                if c["scope"] == "user":
                    c["cleanup"] = self._cleanup_candidates(owner, coll)
                if not tentative or definitive:
                    violations.append(c)
        return {"allowed": not violations, "checks": checks,
                "violations": violations, "owner": owner,
                "tentative": tentative}

    def _project(self, scope, key, coll, limit, old_hash, old_size,
                 new_hash, new_size, scope_sets):
        """对单个作用域做覆盖模拟后的集合投影（引用计数精确判重）。"""
        a_key, t_key, h_key = scope_sets
        t = coll[t_key].get(key, {}) if t_key else {}
        h = coll[h_key].get(key, {})

        # 活动侧改造成 引用计数：同内容被多个活动文件引用时，覆盖其中一个
        # 并不释放该内容（_collect 的去重表丢失了多重引用信息，这里从
        # 文件树重新计数该作用域）。
        active_counts = self._active_ref_counts(scope, key)
        if old_hash and old_hash in active_counts:
            active_counts[old_hash] -= 1

        projected = {}
        for ch, cnt in active_counts.items():
            if cnt > 0:
                projected[ch] = self._hash_size(coll, scope, key, ch)
        projected.update(t)
        projected.update(h)
        if new_hash:
            projected.setdefault(new_hash, int(new_size or 0))
        else:
            # begin 阶段没有真实哈希：哨兵键保证按声明大小全额保守计入
            projected[("__new__", id(coll), key)] = int(new_size or 0)
        projected_bytes = sum(projected.values())

        # 覆盖真正能释放的量（旧内容在活动/回收站/历史中都不再出现）
        reclaimed = 0
        if old_hash and new_hash != old_hash:
            still = (active_counts.get(old_hash, 0) > 0
                     or old_hash in t or old_hash in h)
            if not still:
                reclaimed = int(old_size or 0)

        view = self._scope_view(scope, key, coll, limit)
        view.update({
            "projected_bytes": projected_bytes,
            "projected_free": max(0, limit - projected_bytes) if limit else None,
            "reclaimed_bytes": reclaimed,
            "write_bytes": int(new_size or 0),
            "projected_level": self._level(projected_bytes, limit),
            "over_bytes": max(0, projected_bytes - limit) if limit else 0,
        })
        return view

    def _active_ref_counts(self, scope, key):
        """从文件树实时统计某作用域内活动文件的 content_hash 引用计数。"""
        counts = {}
        with self.meta.lock:
            if scope == "user":
                for _path, inode in self.nn.fs.walk_files():
                    if (inode.get("owner") or "anonymous") == key:
                        ch = inode.get("content_hash")
                        if ch:
                            counts[ch] = counts.get(ch, 0) + 1
            else:
                pfx = key.rstrip("/")
                for path, inode in self.nn.fs.walk_files():
                    if path == key or path.startswith(pfx + "/"):
                        ch = inode.get("content_hash")
                        if ch:
                            counts[ch] = counts.get(ch, 0) + 1
        return counts

    def _hash_size(self, coll, scope, key, ch):
        """在活动去重表里取某哈希的大小；取不到再从回收站/历史兜底。"""
        for name in ("active_u" if scope == "user" else "active_d",
                     "trash_u", "hist_u" if scope == "user" else "hist_d"):
            m = coll.get(name)
            if not m:
                continue
            sz = (m.get(key, {}) or {}).get(ch)
            if sz is not None:
                return int(sz)
        return 0

    @staticmethod
    def _violation_message(v):
        name = v["scope_label"]
        limit = v["limit_bytes"]
        over = v["over_bytes"]
        if v["scope"] == "user":
            return (f"{name}存储配额不足：写入后将达 {v['projected_bytes']} B，"
                    f"超过上限 {limit} B（超出 {over} B）。"
                    f"当前已用 {v['used_bytes']} B（活动 "
                    f"{v['breakdown']['active']} / 回收站 "
                    f"{v['breakdown']['trash']} / 历史版本 "
                    f"{v['breakdown']['history']}），本次写入最多可因覆盖释放 "
                    f"{v['reclaimed_bytes']} B。")
        return (f"{name}目录配额不足：写入后将达 {v['projected_bytes']} B，"
                f"超过上限 {limit} B（超出 {over} B）。"
                f"请联系管理员调整目录配额，或改写到其它目录。")

    def guard_upload(self, username, target_path, new_size, new_hash=None):
        """写路径统一入口：超限抛 QuotaExceeded（携带裁决详情）。"""
        verdict = self.evaluate_write(username, target_path, new_size,
                                      new_hash)
        if not verdict["allowed"]:
            raise QuotaExceeded(verdict["violations"][0])
        return verdict
