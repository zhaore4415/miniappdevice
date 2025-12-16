"use strict";
const common_vendor = require("../../common/vendor.js");
const config = require("../../config.js");
const _sfc_main = {
  data() {
    return {
      apiBase: config.cfg.apiBase,
      statusOptions: ["全部", "空闲", "寄出中", "已归还", "维修中", "报废"],
      statusMap: { Idle: "空闲", Shipping: "寄出中", Returned: "已归还", Repairing: "维修中", Scrapped: "报废" },
      statusLabel: "全部",
      statusKeySel: "",
      q: "",
      list: [],
      showDetail: false,
      detail: {}
    };
  },
  onLoad() {
    this.loadDevices();
  },
  onShow() {
    const tb = this.getTabBar && this.getTabBar();
    if (tb && tb.setData) {
      tb.setData({ selected: 1 });
    }
  },
  onPullDownRefresh() {
    this.refresh();
  },
  methods: {
    refresh() {
      this.loadDevices();
      common_vendor.index.stopPullDownRefresh();
    },
    onStatusChange(e) {
      const i = parseInt(e.detail.value);
      this.statusLabel = this.statusOptions[i];
      this.statusKeySel = this.statusKeyFromLabel(this.statusLabel);
      this.loadDevices();
    },
    statusKeyFromLabel(t) {
      if (t === "全部")
        return "";
      const map = { "空闲": "Idle", "寄出中": "Shipping", "已归还": "Returned", "维修中": "Repairing", "报废": "Scrapped" };
      return map[t] || "";
    },
    statusKey(v) {
      const names = ["Idle", "Shipping", "Returned", "Repairing", "Scrapped"];
      return typeof v === "number" ? names[v] || "" : v;
    },
    statusText(v) {
      const k = this.statusKey(v);
      return this.statusMap[k] || k || "";
    },
    formatTime(v) {
      if (!v)
        return "";
      const d = new Date(v);
      return `${d.getFullYear()}-${(d.getMonth() + 1 + "").padStart(2, "0")}-${(d.getDate() + "").padStart(2, "0")} ${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;
    },
    async loadDevices() {
      const url = `${this.apiBase}/api/devices`;
      const qs = [];
      if (this.statusKeySel)
        qs.push(`status=${this.statusKeySel}`);
      if (this.q)
        qs.push(`q=${encodeURIComponent(this.q)}`);
      const full = qs.length ? `${url}?${qs.join("&")}` : url;
      try {
        const res = await common_vendor.index.request({ url: full, method: "GET" });
        this.list = Array.isArray(res.data) ? res.data : [];
      } catch (e) {
        common_vendor.index.showToast({ title: "加载失败", icon: "none" });
      }
    },
    openDetail(d) {
      this.detail = d;
      this.showDetail = true;
    },
    closeDetail() {
      this.showDetail = false;
    }
  }
};
function _sfc_render(_ctx, _cache, $props, $setup, $data, $options) {
  return common_vendor.e({
    a: common_vendor.t($data.statusLabel),
    b: $data.statusOptions,
    c: common_vendor.o((...args) => $options.onStatusChange && $options.onStatusChange(...args)),
    d: common_vendor.o([($event) => $data.q = $event.detail.value, (...args) => $options.loadDevices && $options.loadDevices(...args)]),
    e: $data.q,
    f: common_vendor.o((...args) => $options.refresh && $options.refresh(...args)),
    g: common_vendor.f($data.list, (d, k0, i0) => {
      return {
        a: common_vendor.t(d.SN || d.sn),
        b: common_vendor.t($options.statusText(d.status)),
        c: common_vendor.n("s-" + $options.statusKey(d.status)),
        d: common_vendor.t(d.name || ""),
        e: common_vendor.t(d.lastShipAddress || ""),
        f: common_vendor.t($options.formatTime(d.lastShipAt)),
        g: common_vendor.t($options.formatTime(d.lastReturnAt)),
        h: d.SN || d.sn,
        i: common_vendor.o(($event) => $options.openDetail(d), d.SN || d.sn)
      };
    }),
    h: common_vendor.o((...args) => $options.refresh && $options.refresh(...args)),
    i: $data.showDetail
  }, $data.showDetail ? {
    j: common_vendor.o((...args) => $options.closeDetail && $options.closeDetail(...args)),
    k: common_vendor.t($data.detail.SN || $data.detail.sn),
    l: common_vendor.t($data.detail.name || ""),
    m: common_vendor.t($data.detail.model || ""),
    n: common_vendor.t($data.detail.owner || ""),
    o: common_vendor.t($options.statusText($data.detail.status)),
    p: common_vendor.t($data.detail.lastShipAddress || ""),
    q: common_vendor.t($options.formatTime($data.detail.lastShipAt)),
    r: common_vendor.t($options.formatTime($data.detail.lastReturnAt))
  } : {});
}
const MiniProgramPage = /* @__PURE__ */ common_vendor._export_sfc(_sfc_main, [["render", _sfc_render]]);
wx.createPage(MiniProgramPage);
//# sourceMappingURL=../../../.sourcemap/mp-weixin/pages/index/index.js.map
