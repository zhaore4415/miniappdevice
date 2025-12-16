<template>
  <view class="page">
    <view class="bar">
      <picker mode="selector" :range="statusOptions" @change="onStatusChange">
        <view class="btn">{{statusLabel}}</view>
      </picker>
      <input class="search" placeholder="按SN或名称" v-model="q" @input="loadDevices" />
      <button class="btn" @click="refresh">刷新</button>
    </view>
    <scroll-view scroll-y class="list">
      <view v-for="d in list" :key="d.SN||d.sn" class="card" @click="openDetail(d)">
        <view class="row">
          <text class="sn">{{d.SN||d.sn}}</text>
          <text class="status" :class="'s-'+statusKey(d.status)">{{statusText(d.status)}}</text>
        </view>
        <view class="row"><text class="label">名称</text><text class="val">{{d.name||''}}</text></view>
        <view class="row"><text class="label">寄出地址</text><text class="val">{{d.lastShipAddress||''}}</text></view>
        <view class="row"><text class="label">寄出时间</text><text class="val">{{formatTime(d.lastShipAt)}}</text></view>
        <view class="row"><text class="label">归还时间</text><text class="val">{{formatTime(d.lastReturnAt)}}</text></view>
      </view>
    </scroll-view>
    <view class="footer">
      <view class="footer-item disabled">寄出</view>
      <view class="footer-item active" @click="refresh">设备列表</view>
      <view class="footer-item disabled">归还</view>
    </view>
    <view class="modal" v-if="showDetail">
      <view class="detail">
        <view class="row head"><text>设备详情</text><button class="btn" @click="closeDetail">关闭</button></view>
        <view class="row"><text class="label">SN</text><text class="val">{{detail.SN||detail.sn}}</text></view>
        <view class="row"><text class="label">名称</text><text class="val">{{detail.name||''}}</text></view>
        <view class="row"><text class="label">型号</text><text class="val">{{detail.model||''}}</text></view>
        <view class="row"><text class="label">负责人</text><text class="val">{{detail.owner||''}}</text></view>
        <view class="row"><text class="label">状态</text><text class="val">{{statusText(detail.status)}}</text></view>
        <view class="row"><text class="label">寄出地址</text><text class="val">{{detail.lastShipAddress||''}}</text></view>
        <view class="row"><text class="label">寄出时间</text><text class="val">{{formatTime(detail.lastShipAt)}}</text></view>
        <view class="row"><text class="label">归还时间</text><text class="val">{{formatTime(detail.lastReturnAt)}}</text></view>
      </view>
    </view>
  </view>
  </template>
  <script>
  import cfg from '../../config.js'
  export default {
    data(){
      return {
        apiBase: cfg.apiBase,
        statusOptions: ['全部','空闲','寄出中','已归还','维修中','报废'],
        statusMap: { Idle:'空闲', Shipping:'寄出中', Returned:'已归还', Repairing:'维修中', Scrapped:'报废' },
        statusLabel: '全部',
        statusKeySel: '',
        q: '',
        list: [],
        showDetail: false,
        detail: {}
      }
    },
    onLoad(){
      this.loadDevices();
    },
    onShow(){
      const tb = this.getTabBar && this.getTabBar()
      if(tb && tb.setData){ tb.setData({ selected: 1 }) }
    },
    onPullDownRefresh(){
      this.refresh();
    },
    methods:{
      refresh(){ this.loadDevices(); uni.stopPullDownRefresh(); },
      onStatusChange(e){ const i = parseInt(e.detail.value); this.statusLabel = this.statusOptions[i]; this.statusKeySel = this.statusKeyFromLabel(this.statusLabel); this.loadDevices(); },
      statusKeyFromLabel(t){ if(t==='全部') return ''; const map = { '空闲':'Idle','寄出中':'Shipping','已归还':'Returned','维修中':'Repairing','报废':'Scrapped' }; return map[t] || ''; },
      statusKey(v){ const names = ['Idle','Shipping','Returned','Repairing','Scrapped']; return typeof v==='number'? (names[v]||'') : v; },
      statusText(v){ const k = this.statusKey(v); return this.statusMap[k] || k || ''; },
      formatTime(v){ if(!v) return ''; const d = new Date(v); return `${d.getFullYear()}-${(d.getMonth()+1+'').padStart(2,'0')}-${(d.getDate()+'').padStart(2,'0')} ${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`; },
      async loadDevices(){
        const url = `${this.apiBase}/api/devices`;
        const qs = [];
        if(this.statusKeySel) qs.push(`status=${this.statusKeySel}`);
        if(this.q) qs.push(`q=${encodeURIComponent(this.q)}`);
        const full = qs.length? `${url}?${qs.join('&')}` : url;
        try{
          const res = await uni.request({ url: full, method:'GET' });
          this.list = Array.isArray(res.data)? res.data : [];
        }catch(e){ uni.showToast({ title:'加载失败', icon:'none' }); }
      },
      openDetail(d){ this.detail = d; this.showDetail = true; },
      closeDetail(){ this.showDetail = false; }
    }
  }
  </script>
  <style>
  .page{ padding: 20rpx; }
  .bar{ display:flex; gap: 16rpx; align-items:center; }
  .btn{ padding: 10rpx 20rpx; background:#3b82f6; color:#fff; border-radius: 8rpx; font-size: 26rpx; }
  .search{ flex:1; padding: 10rpx 20rpx; border:1rpx solid #ddd; border-radius: 8rpx; background:#fff; }
  .list{ height: calc(100vh - 260rpx); margin-top: 20rpx; }
  .card{ background:#fff; border:1rpx solid #eee; border-radius: 12rpx; padding: 20rpx; margin-bottom: 16rpx; }
  .row{ display:flex; justify-content:space-between; margin-bottom: 10rpx; }
  .sn{ font-weight: bold; }
  .label{ color:#666; width:160rpx; }
  .val{ flex:1; text-align:right; }
  .status{ padding: 6rpx 12rpx; border-radius: 8rpx; font-size: 24rpx; }
  .s-Idle{ background:#eaf3ff; color:#2563eb; }
  .s-Shipping{ background:#eafaf5; color:#0f766e; }
  .s-Returned{ background:#f1f5f9; color:#334155; }
  .s-Repairing{ background:#fff7ed; color:#ea580c; }
  .s-Scrapped{ background:#fce7f3; color:#be185d; }
  .modal{ position:fixed; inset:0; background:rgba(0,0,0,.35); display:flex; align-items:center; justify-content:center; }
  .detail{ width: 640rpx; background:#fff; border-radius: 12rpx; padding: 20rpx; }
  .head{ align-items:center; }
  .footer{ position:fixed; left:0; right:0; bottom:0; height: 120rpx; background:#fff; border-top:1rpx solid #eee; display:flex; }
  .footer-item{ flex:1; text-align:center; line-height:120rpx; font-size: 34rpx; color:#666; }
  .footer-item.active{ color:#3b82f6; font-weight: 600; }
  .footer-item.disabled{ color:#999; }
  </style>
