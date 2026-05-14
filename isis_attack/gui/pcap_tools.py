"""ISIS 报文嗅探 / pcap 导入 / 报文浏览器。"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


def _parse_isis_packet(raw: bytes) -> dict | None:
    """解析 ISIS 报文，提取关键字段。"""
    if len(raw) < 30:
        return None
    if raw[14] != 0xFE or raw[15] != 0xFE or raw[16] != 0x03:
        return None
    isis = raw[17:]
    if len(isis) < 8 or isis[0] != 0x83:
        return None
    hdr_len = isis[1]
    pdu_type = isis[4]
    id_len = isis[3] or 6
    if hdr_len < 8 + id_len:
        return None
    sys_id_bytes = isis[8:8 + id_len]
    hex_str = sys_id_bytes.hex()
    sys_id = ".".join(hex_str[i:i+4] for i in range(0, len(hex_str), 4))

    pdu_names = {15: "L1 IIH", 16: "L2 IIH", 17: "P2P IIH",
                 18: "L1 LSP", 20: "L2 LSP",
                 24: "L1 CSNP", 25: "L2 CSNP",
                 26: "L1 PSNP", 27: "L2 PSNP"}
    result = {
        "pkt_type": pdu_names.get(pdu_type, f"PDU-{pdu_type}"),
        "sys_id": sys_id, "pdu_type": pdu_type,
        "src_mac": ":".join(f"{b:02x}" for b in raw[6:12]),
        "dst_mac": ":".join(f"{b:02x}" for b in raw[0:6]),
        "_raw": raw,
    }
    body = isis[hdr_len:]
    if pdu_type in (15, 16, 17) and len(body) >= 8:
        tlvs = isis[hdr_len + 8:]
        result.update(_parse_tlvs(tlvs))
    elif pdu_type in (18, 20) and len(body) >= 17:
        result["lifetime"] = int.from_bytes(body[0:2], "big")
        result["sequence"] = int.from_bytes(body[10:14], "big")
        tlvs = body[17:]
        result.update(_parse_tlvs(tlvs))
    elif pdu_type in (24, 25):
        # CSNP/PSNP — just basic info
        pass
    return result


def _parse_tlvs(data: bytes) -> dict:
    result = {}
    offset = 0
    while offset + 2 <= len(data):
        t = data[offset]
        ln = data[offset + 1]
        if offset + 2 + ln > len(data):
            break
        val = data[offset + 2:offset + 2 + ln]
        if t == 1 and ln >= 1 and val[0] + 1 <= ln:
            result["area_addr"] = val[1:1 + val[0]].hex()
        elif t == 129 and ln >= 1:
            result["nlpid"] = f"0x{val[0]:02X}"
        elif t == 137:
            result["hostname"] = val.decode("ascii", errors="replace")
        elif t == 128 and ln >= 12:
            m = val[0] & 0x3F
            ip = ".".join(str(b) for b in val[4:8])
            mask = ".".join(str(b) for b in val[8:12])
            result["ip_reach"] = f"{ip}/{mask}"
            result["metric"] = m
        elif t == 6:
            result["neighbors"] = ln // 6
        offset += 2 + ln
    return result


# -- 嗅探 --

def sniff_isis(iface: str, timeout: int = 10) -> list[dict]:
    """在指定接口嗅探 ISIS 报文（无 BPF 过滤器，在 Python 中过滤）。"""
    results = []
    try:
        from scapy.all import sniff
        for pkt in sniff(iface=iface, timeout=timeout, store=True):
            p = _parse_isis_packet(bytes(pkt))
            if p:
                results.append(p)
    except Exception:
        import traceback; traceback.print_exc()
    return results


def sniff_isis_async(iface: str, timeout: int = 60):
    """异步嗅探 ISIS 报文（无 BPF 过滤器，在解析时过滤）。"""
    from scapy.all import AsyncSniffer
    s = AsyncSniffer(iface=iface, timeout=timeout, store=True)
    s.start()
    return s


def parse_sniff_results(sniffer) -> list[dict]:
    return [p for pkt in sniffer.results
            if (p := _parse_isis_packet(bytes(pkt)))]


# -- pcap 导入 --

def read_pcap(path: str) -> list[dict]:
    results = []
    try:
        from scapy.utils import rdpcap
        for pkt in rdpcap(path):
            p = _parse_isis_packet(bytes(pkt))
            if p:
                results.append(p)
    except Exception:
        import traceback; traceback.print_exc()
    return results


# -- 报文浏览器 --

class PacketBrowser(tk.Toplevel):
    def __init__(self, parent, packets: list[dict], auto_fill_callback=None):
        super().__init__(parent)
        self.title(f"ISIS 报文浏览器 — {len(packets)} 个报文")
        self.geometry("800x480")
        self.resizable(True, True)
        self.transient(parent)
        self._packets = packets
        self._auto_fill = auto_fill_callback
        self._build()
        self._populate()

    def _build(self):
        cols = ("type", "src_mac", "sys_id", "summary")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse", height=12)
        for col, hdr, w in [("type", "类型", 100), ("src_mac", "源 MAC", 160),
                             ("sys_id", "System ID", 160), ("summary", "摘要", 350)]:
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w, anchor="w")
        self._tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))

        bot = ttk.Frame(self)
        bot.pack(fill=tk.X, padx=10, pady=8)

        self._detail = tk.Text(bot, font=("Consolas", 9), height=8,
                               bg="#1e1e1e", fg="#d4d4d4",
                               relief=tk.FLAT, state=tk.DISABLED, wrap=tk.NONE)
        self._detail.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        bar = ttk.Frame(bot)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="应用到表单", command=self._apply).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="保存为 pcap", command=self._save).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="关闭", command=self.destroy).pack(side=tk.RIGHT, padx=2)
        self._tree.bind("<<TreeviewSelect>>", self._on_sel)

    def _populate(self):
        for pkt in self._packets:
            s = []
            if "area_addr" in pkt:
                s.append(f"Area={pkt['area_addr']}")
            if "hostname" in pkt:
                s.append(f"Host={pkt['hostname']}")
            if "ip_reach" in pkt:
                s.append(f"Reach={pkt['ip_reach']} m={pkt.get('metric','?')}")
            if "lifetime" in pkt:
                s.append(f"Seq=0x{pkt.get('sequence',0):08X} Life={pkt['lifetime']}s")
            self._tree.insert("", tk.END, values=(
                pkt.get("pkt_type", "?"), pkt.get("src_mac", "?"),
                pkt.get("sys_id", "?"), "  |  ".join(s)))

    def _on_sel(self, _):
        sel = self._tree.selection()
        if not sel:
            return
        pkt = self._packets[self._tree.index(sel[0])]
        lines = [f"类型: {pkt.get('pkt_type','?')}", f"Src: {pkt.get('src_mac','?')}",
                 f"Dst: {pkt.get('dst_mac','?')}", f"System ID: {pkt.get('sys_id','?')}"]
        for k, lbl in [("area_addr", "Area"), ("hostname", "Host"), ("ip_reach", "IP"),
                        ("metric", "Metric"), ("lifetime", "Lifetime"), ("sequence", "Seq"),
                        ("neighbors", "Neighbors"), ("nlpid", "NLPID")]:
            if k in pkt:
                lines.append(f"{lbl}: {pkt[k]}")
        self._detail.configure(state=tk.NORMAL)
        self._detail.delete("1.0", tk.END)
        self._detail.insert("1.0", "\n".join(lines))
        self._detail.configure(state=tk.DISABLED)

    def _apply(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择一个报文")
            return
        pkt = self._packets[self._tree.index(sel[0])]
        if self._auto_fill:
            self._auto_fill(pkt)
        self.destroy()

    def _save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("pcap files", "*.pcap"), ("All files", "*.*")],
            title="保存报文为 pcap")
        if not path:
            return
        try:
            from scapy.utils import wrpcap
            pkts = [p["_raw"] for p in self._packets if p.get("_raw")]
            if pkts:
                wrpcap(path, pkts)
        except Exception as e:
            messagebox.showerror("保存失败", str(e))
