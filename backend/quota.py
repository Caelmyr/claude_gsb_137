# -*- coding: utf-8 -*-
"""
quota.py — 用户 / 目录存储空间配额
==================================

配额口径必须覆盖 NameNode 仍然保护的全部逻辑数据，而不能只统计活动文件：

* active：当前活动 inode 树中的文件；
* trash：回收站中的文件。删除只是把 inode 挂到 .trash，块仍被 GC 保护，
  只有“彻底删除”且历史快照不再引用后才释放；
* history：全部提交快照中的历史版本。同一路径、同一内容哈希在活动文件、
  回收站和历史版本之间只计一次，避免把共享同一个不可变块的数据重复计费；
* reserved：进行中的上传会话，按完整文件大小预占，避免多个并发上传绕过上限。

目录配额按路径前缀作用于其全部子目录；用户配额按文件/快照记录的 owner
归属。配额在行级别展示活动、回收站、历史版本和预占空间，超限时同时返回
可清理项，帮助用户判断需要释放多少字节。
"""

import threading
from collections import defaultdict

from .util import join_path, norm_path, now


ACTIVE = 1
TRASH = 2
HISTORY = 4
PENDING = 8


class QuotaError(Exception):
    """配额模块通用错误。"""


class QuotaExceeded(QuotaError):
    def __init__(self, message, payload):
        super().__init__(message)
        self.status = 507
        self.payload = payload


class QuotaManager:
    def __init__(self, nn):
        self.nn = nn
        self.meta = nn.meta
        self.lock = threading.RLock()

    # ------------------------------------------------------------------ 初始化
    def init_doc(self):
        with self.meta.lock:
            q = self.meta.get("quotas")
            q.setdefault("users", {})
            q.setdefault("directories", {})
            q.setdefault("updated_at", now())
            self.meta.touch("quotas")

    def _doc(self):
        return self.meta.get("quotas")

    # ------------------------------------------------------------------ 限额
    @staticmethod
    def _parse_limit(limit):
        if limit is None or limit == "":
            return None
        try:
            value = int(limit)
        except (TypeError, ValueError):
            raise QuotaError("配额必须是字节整数；0 或空表示不限")
        if value < 0:
            raise QuotaError("配额不能为负数")
        return value or None

    def set_user_quota(self, username, limit, actor="admin", note=""):
        username = (username or "").strip().lower()
        if not username:
            raise QuotaError("用户名不能为空")
        if not self.nn.auth.get_user(username):
            raise QuotaError(f"用户不存在: {username}")
        value = self._parse_limit(limit)
        with self.meta.lock:
            users = self._doc().setdefault("users", {})
            if value is None:
                users.pop(username, None)
            else:
                record = users.setdefault(username, {})
                record.update({"limit": value, "updated_at": now(),
                               "updated_by": actor, "note": note or ""})
            self._doc()["updated_at"] = now()
            self.meta.touch("quotas")
        return self.get_quota("user", username)

    def set_directory_quota(self, path, limit, actor="admin", note=""):
        path = norm_path(path)
        inode = self.nn.fs.resolve(path, must_exist=False)
        if inode and inode.get("type") != "dir":
            raise QuotaError(f"配额只能设置在目录上: {path}")
        value = self._parse_limit(limit)
        with self.meta.lock:
            dirs = self._doc().setdefault("directories", {})
            if value is None:
                dirs.pop(path, None)
            else:
                dirs.setdefault(path, {}).update({"path": path, "limit": value,
                               "updated_at": now(), "updated_by": actor,
                               "note": note or ""})
            self._doc()["updated_at"] = now()
            self.meta.touch("quotas")
        return self.get_quota("directory", path)

    def delete_quota(self, scope, name):
        if scope == "user":
            return self.set_user_quota(name, None)
        if scope == "directory":
            return self.set_directory_quota(name, None)
        raise QuotaError("scope 必须是 user 或 directory")

    def _limits(self):
        q = self._doc()
        return (dict(q.get("users", {})), dict(q.get("directories", {})))

    def _limit(self, scope, name, user_limits=None, dir_limits=None):
        user_limits, dir_limits = (
            (user_limits, dir_limits) if user_limits is not None or dir_limits is not None
            else self._limits())
        table = user_limits if scope == "user" else dir_limits
        rec = table.get(name) or {}
        return rec.get("limit")

    # ------------------------------------------------------------------ 扫描
    @staticmethod
    def _ancestors(path):
        path = norm_path(path)
        yield "/"
        cur = ""
        for seg in [s for s in path.split("/") if s]:
            cur += "/" + seg
            yield cur

    @staticmethod
    def _normal_key(path, node):
        digest = node.get("content_hash")
        if not digest:
            digest = ("blocks", tuple(node.get("block_ids", [])))
        return norm_path(path), digest

    def _new_scope_map(self):
        return {"key_size": {}, "key_cat": defaultdict(int),
                "entries": defaultdict(int), "trash_items": {},
                "trash_key_items": defaultdict(set),
                "history_records": {}, "active_records": {}}

    def _add_key(self, maps, scope, owner_path, key, size, category):
        scope_id = owner_path
        if not scope_id:
            return
        data = maps[scope].setdefault(scope_id, self._new_scope_map())
        old = data["key_size"].get(key)
        if old is None or size > old:
            data["key_size"][key] = size
        data["key_cat"][key] |= category
        data["entries"][category] += 1

    def _add_retained(self, maps, owner, path, node, category, meta=None):
        size = int(node.get("size", 0) or 0)
        key = self._normal_key(path, node)
        meta = meta or {}
        if owner:
            self._add_key(maps, "user", owner, key, size, category)
            record_id = ("user", owner, key)
            if category == ACTIVE:
                maps["_active"][record_id] = {
                    "path": norm_path(path), "size": size,
                    "name": node.get("name", path.rsplit("/", 1)[-1])}
            elif category == HISTORY:
                maps["_history"][record_id] = meta
        for directory in self._ancestors(path):
            self._add_key(maps, "directory", directory, key, size, category)
            record_id = ("directory", directory, key)
            if category == ACTIVE:
                maps["_active"][record_id] = {
                    "path": norm_path(path), "size": size,
                    "name": node.get("name", path.rsplit("/", 1)[-1])}
            elif category == HISTORY:
                maps["_history"][record_id] = meta

    def _add_trash_record(self, maps, owner, path, node, item):
        size = int(node.get("size", 0) or 0)
        key = self._normal_key(path, node)
        item_id = item["id"]
        for scope, scope_id in [("user", owner)] + [
                ("directory", d) for d in self._ancestors(path)]:
            if not scope_id:
                continue
            data = maps[scope].setdefault(scope_id, self._new_scope_map())
            data["trash_items"][item_id] = {
                "id": item_id, "name": item.get("name", item_id),
                "original_path": item.get("original_path", path),
                "size": item.get("size", size), "deleted_by": item.get("deleted_by"),
                "expires_at": item.get("expires_at")}
            data["trash_key_items"][key].add(item_id)
        self._add_retained(maps, owner, path, node, TRASH)

    def _add_history_record(self, maps, owner, path, entry, commit):
        key = self._normal_key(path, entry)
        meta = {"path": norm_path(path), "size": int(entry.get("size", 0) or 0),
                "commit": commit.get("id"), "message": commit.get("message", ""),
                "ts": commit.get("ts"), "author": commit.get("author", "")}
        for scope, scope_id in [("user", owner)] + [
                ("directory", d) for d in self._ancestors(path)]:
            record_id = (scope, scope_id, key)
            maps["_history"].setdefault(record_id, meta)
        self._add_retained(maps, owner, path, entry, HISTORY, meta)

    def _build_maps(self, sessions, skip_active_path=None,
                    candidate_session=None):
        maps = {"user": {}, "directory": {},
                "_active": {}, "_history": {}}
        skip_active_path = norm_path(skip_active_path) if skip_active_path else None
        fs = self.nn.fs
        inodes = fs._inodes()

        for path, node in fs.all_files():
            if path == skip_active_path:
                continue
            self._add_retained(maps, node.get("owner", "admin"), path, node,
                               ACTIVE)

        recycle = self.meta.get("recycle").get("items", {})
        for item in recycle.values():
            root = inodes.get(item.get("inode"))
            if not root:
                continue
            stack = [(root, item.get("original_path", "/"))]
            while stack:
                cur, cur_path = stack.pop()
                if cur.get("type") == "file":
                    self._add_trash_record(
                        maps, cur.get("owner") or item.get("deleted_by", "admin"),
                        norm_path(cur_path), cur, item)
                else:
                    for cid in cur.get("children", []):
                        child = inodes.get(cid)
                        if child:
                            stack.append((child, join_path(cur_path, child["name"])))

        commits = self.meta.get("versions").get("commits", {})
        for commit in commits.values():
            for path, entry in commit.get("snapshot", {}).items():
                self._add_history_record(
                    maps, entry.get("owner", "admin"), path, entry, commit)

        for sess in sessions:
            self._add_pending(maps, sess)
        if candidate_session:
            self._add_pending(maps, candidate_session)
        return maps

    def _add_pending(self, maps, sess):
        target = norm_path(join_path(sess.get("path", "/"), sess.get("filename", "")))
        size = int(sess.get("size", 0) or 0)
        key = ("__pending__", sess.get("id"), target)
        owner = sess.get("user") or "anonymous"
        self._add_key(maps, "user", owner, key, size, PENDING)
        for directory in self._ancestors(target):
            self._add_key(maps, "directory", directory, key, size, PENDING)

    def _active_sessions(self, exclude_id=None):
        with self.nn.session_lock:
            out = []
            for sess in self.nn.sessions.values():
                if sess.get("completed") or sess.get("id") == exclude_id:
                    continue
                out.append({k: sess.get(k) for k in (
                    "id", "path", "filename", "size", "user", "committing")})
            return out

    # ------------------------------------------------------------------ 汇总
    def _components(self, data):
        comp = {"active": 0, "trash": 0, "history": 0, "reserved": 0}
        counts = {"active_files": 0, "trash_files": 0,
                  "history_versions": 0, "pending_uploads": 0}
        for key, size in data["key_size"].items():
            cat = data["key_cat"].get(key, 0)
            if cat & PENDING:
                comp["reserved"] += size
                counts["pending_uploads"] += 1
            elif cat & ACTIVE:
                comp["active"] += size
                counts["active_files"] += 1
            elif cat & HISTORY:
                comp["history"] += size
                counts["history_versions"] += 1
            elif cat & TRASH:
                comp["trash"] += size
                counts["trash_files"] += 1
        # 条目次数用于解释规模；字节组件仍按唯一键去重。
        counts["trash_entries"] = len(data["trash_items"])
        return comp, counts

    def _cleanup(self, maps, scope, scope_id, data):
        trash = []
        item_bytes = defaultdict(int)
        for key, item_ids in data["trash_key_items"].items():
            cat = data["key_cat"].get(key, 0)
            # 只有该回收站条目独占、且活动/历史均不再引用时，清空它才立即释放。
            if cat == TRASH and len(item_ids) == 1:
                item_id = next(iter(item_ids))
                item_bytes[item_id] += data["key_size"].get(key, 0)
        for item_id, releasable in item_bytes.items():
            item = dict(data["trash_items"].get(item_id, {}))
            item["releasable_bytes"] = releasable
            trash.append(item)
        trash.sort(key=lambda x: x.get("releasable_bytes", 0), reverse=True)

        hist_by_path = defaultdict(int)
        hist_meta = {}
        for (s, sid, key), meta in maps["_history"].items():
            if s == scope and sid == scope_id and data["key_cat"].get(key) == HISTORY:
                hist_by_path[meta["path"]] += data["key_size"].get(key, 0)
                hist_meta.setdefault(meta["path"], meta)
        history = []
        for path, size in hist_by_path.items():
            meta = hist_meta[path]
            history.append({"path": path, "size": size,
                            "commit": meta.get("commit"),
                            "message": meta.get("message", ""),
                            "ts": meta.get("ts")})
        history.sort(key=lambda x: x["size"], reverse=True)

        active_by_path = {}
        for (s, sid, key), meta in maps["_active"].items():
            if s == scope and sid == scope_id and data["key_cat"].get(key, 0) & ACTIVE:
                active_by_path[meta["path"]] = meta["size"]
        active = [{"path": p, "size": s}
                  for p, s in active_by_path.items()]
        active.sort(key=lambda x: x["size"], reverse=True)
        return {"trash": trash[:8], "history": history[:8],
                "active": active[:8],
                "immediate_releasable_bytes": sum(i["releasable_bytes"]
                                                  for i in trash)}

    def _row(self, maps, scope, scope_id, limit=None):
        data = maps[scope].get(scope_id) or self._new_scope_map()
        components, counts = self._components(data)
        retained = components["active"] + components["trash"] + components["history"]
        reserved = components["reserved"]
        used = retained + reserved
        cleanup = self._cleanup(maps, scope, scope_id, data)
        row = {
            "scope": scope,
            "limit": limit,
            "used": used,
            "retained_bytes": retained,
            "reserved_bytes": reserved,
            "remaining": None if limit is None else max(0, limit - used),
            "over": max(0, used - limit) if limit is not None else 0,
            "over_limit": limit is not None and used > limit,
            "usage_ratio": round(used / limit, 4) if limit else None,
            "components": components,
            "counts": counts,
            "cleanup": cleanup,
        }
        if scope == "directory":
            row["path"] = scope_id
        else:
            row["username"] = scope_id
        return row

    def overview(self):
        sessions = self._active_sessions()
        with self.meta.lock:
            user_limits, dir_limits = self._limits()
            maps = self._build_maps(sessions)
            users = [u["username"] for u in self.nn.auth.list_users()]
            users.extend(k for k in user_limits if k not in users)

            paths = set(dir_limits.keys())
            root = self.nn.fs.get_inode(self.nn.fs.root_id)
            if root:
                stack = [("/", root)]
                inodes = self.nn.fs._inodes()
                while stack:
                    p, node = stack.pop()
                    paths.add(norm_path(p))
                    for cid in node.get("children", []):
                        child = inodes.get(cid)
                        if child and child.get("type") == "dir":
                            stack.append((join_path(p, child["name"]), child))

            user_rows = [self._row(
                maps, "user", name, user_limits.get(name, {}).get("limit"))
                for name in sorted(users)]
            dir_rows = [self._row(
                maps, "directory", path, dir_limits.get(path, {}).get("limit"))
                for path in sorted(paths)]
            dir_rows.sort(key=lambda r: (not r["over_limit"], -r["used"], r["path"]))
            user_rows.sort(key=lambda r: (not r["over_limit"], -r["used"], r["username"]))
            return {"users": user_rows, "directories": dir_rows,
                    "user_limits": user_limits, "directory_limits": dir_limits}

    def my_status(self, user, path="/"):
        path = norm_path(path)
        # 文件路径按其父目录判定；目录路径按全部祖先判定。
        inode = self.nn.fs.resolve(path, must_exist=False)
        if inode and inode.get("type") == "file":
            target_dir = "/".join(path.split("/")[:-1]) or "/"
        else:
            target_dir = path
        sessions = self._active_sessions()
        with self.meta.lock:
            user_limits, dir_limits = self._limits()
            maps = self._build_maps(sessions)
            username = (user or {}).get("username", "anonymous")
            user_row = self._row(maps, "user", username,
                                 user_limits.get(username, {}).get("limit"))
            dirs = [self._row(maps, "directory", d,
                              dir_limits.get(d, {}).get("limit"))
                    for d in self._ancestors(target_dir)
                    if d in dir_limits or d == target_dir or d == "/"]
            return {"user": user_row, "directories": dirs, "path": target_dir}

    def get_quota(self, scope, name):
        if scope == "user":
            name = name.lower()
        else:
            name = norm_path(name)
        sessions = self._active_sessions()
        with self.meta.lock:
            ul, dl = self._limits()
            maps = self._build_maps(sessions)
            limit = (ul if scope == "user" else dl).get(name, {}).get("limit")
            return self._row(maps, scope, name, limit)

    # ------------------------------------------------------------------ 拦截
    def evaluate_write(self, path, filename, size, user, exclude_session=None):
        target = norm_path(join_path(path, filename))
        candidate = {"id": exclude_session or f"check-{user}-{target}",
                     "path": path, "filename": filename, "size": size,
                     "user": user}
        sessions = self._active_sessions(exclude_session)
        with self.meta.lock:
            user_limits, dir_limits = self._limits()
            maps = self._build_maps(
                sessions, skip_active_path=target,
                candidate_session=candidate)
            affected_users = [user] if user else []
            affected_dirs = list(self._ancestors(target))
            violations = []
            for scope, names, limits in (
                    ("user", affected_users, user_limits),
                    ("directory", affected_dirs, dir_limits)):
                for name in names:
                    limit = limits.get(name, {}).get("limit")
                    if limit is None:
                        continue
                    row = self._row(maps, scope, name, limit)
                    if row["over_limit"]:
                        violations.append(row)
            if violations:
                cleanup = self._violation_cleanup(
                    maps, [("user", name) for name in affected_users] +
                    [("directory", name) for name in affected_dirs])
                self._raise(violations, target, cleanup)
            return {"allowed": True, "target": target,
                "user": self._row(maps, "user", user,
                                  user_limits.get(user, {}).get("limit"))
                if user else None,
                "directories": [
                    self._row(maps, "directory", d,
                              dir_limits.get(d, {}).get("limit"))
                    for d in affected_dirs]}

    def _violation_cleanup(self, maps, scopes):
        trash = {}
        history = defaultdict(int)
        active = {}
        for scope, name in scopes:
            data = maps[scope].get(name)
            if not data:
                continue
            for key, item_ids in data["trash_key_items"].items():
                cat = data["key_cat"].get(key, 0)
                if cat == TRASH and len(item_ids) == 1:
                    item_id = next(iter(item_ids))
                    rec = dict(data["trash_items"][item_id])
                    rec["scope"] = scope
                    rec["releasable_bytes"] = data["key_size"].get(key, 0)
                    old = trash.get(item_id)
                    if not old or rec["releasable_bytes"] > old["releasable_bytes"]:
                        trash[item_id] = rec
            for (s, sid, key), meta in maps["_history"].items():
                if s == scope and sid == name and data["key_cat"].get(key) == HISTORY:
                    history[meta["path"]] += data["key_size"].get(key, 0)
            for (s, sid, key), meta in maps["_active"].items():
                if s == scope and sid == name and data["key_cat"].get(key, 0) & ACTIVE:
                    active[meta["path"]] = meta["size"]
        trash_items = sorted(trash.values(),
                             key=lambda x: x.get("releasable_bytes", 0),
                             reverse=True)[:8]
        history_items = [{"path": p, "size": s} for p, s in
                         sorted(history.items(), key=lambda x: x[1], reverse=True)[:8]]
        active_items = [{"path": p, "size": s} for p, s in
                        sorted(active.items(), key=lambda x: x[1], reverse=True)[:8]]
        return {
            "trash": trash_items,
            "history": history_items,
            "active": active_items,
            "immediate_releasable_bytes": sum(i["releasable_bytes"]
                                              for i in trash_items),
        }

    def _raise(self, violations, target, cleanup):
        parts = []
        for v in violations:
            label = f"用户 {v['username']}" if v["scope"] == "user" else f"目录 {v['path']}"
            parts.append(
                f"{label} 将超出 {v['over']} 字节（上限 {v['limit']}，"
                f"写入后占用 {v['used']}，剩余额度 {max(0, v['remaining'])}）")
        message = "存储空间不足，上传已拦截：" + "；".join(parts)
        if cleanup["trash"]:
            top = ", ".join(f"{i['name']}（可释放 {i['releasable_bytes']} 字节）"
                            for i in cleanup["trash"][:3])
            message += f"。彻底清空回收站可立即释放 {cleanup['immediate_releasable_bytes']} 字节：{top}"
        if cleanup["history"]:
            top = ", ".join(f"{i['path']}（{i['size']} 字节）"
                            for i in cleanup["history"][:3])
            message += f"；另有历史版本独占数据需管理员压缩/清理：{top}"
        if cleanup["active"] and not cleanup["trash"]:
            message += ("；可先删除不需要的活动文件，再到回收站彻底清空才会释放额度")
        payload = {"error": message, "code": "QUOTA_EXCEEDED",
                   "target": target, "violations": violations,
                   "cleanup": cleanup}
        raise QuotaExceeded(message, payload)
