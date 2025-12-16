"use strict";
const common_vendor = require("../../common/vendor.js");
const _sfc_main = {
  onShow() {
    common_vendor.index.showToast({ title: "暂不提供", icon: "none" });
    setTimeout(() => {
      common_vendor.index.switchTab({ url: "/pages/index/index" });
    }, 500);
  }
};
function _sfc_render(_ctx, _cache, $props, $setup, $data, $options) {
  return {};
}
const MiniProgramPage = /* @__PURE__ */ common_vendor._export_sfc(_sfc_main, [["render", _sfc_render]]);
wx.createPage(MiniProgramPage);
//# sourceMappingURL=../../../.sourcemap/mp-weixin/pages/ship/index.js.map
