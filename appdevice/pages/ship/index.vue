<template>
  <view class="wrap">
    <text class="txt">寄出功能暂不提供</text>
  </view>
</template>
<script>
export default {
  onShow(){
    uni.showToast({ title:'暂不提供', icon:'none' });
    setTimeout(()=>{ uni.switchTab({ url:'/pages/index/index' }); }, 500);
  }
}
</script>
<style>
.wrap{ height:100vh; align-items:center; justify-content:center; display:flex; }
.txt{ color:#666; }
</style>
