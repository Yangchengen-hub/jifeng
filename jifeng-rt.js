// 极风工作室 - 实时时间更新（极简兼容版）
(function(){
  'use strict';
  function update(){
    var el = document.getElementById('ftt');
    if(!el) return;
    var now = new Date();
    var y=now.getFullYear(),m=now.getMonth()+1,d=now.getDate();
    var h=now.getHours(),mn=now.getMinutes(),s=now.getSeconds();
    el.textContent = y+'-'+(m<10?'0':'')+m+'-'+(d<10?'0':'')+d+' '+(h<10?'0':'')+h+':'+(mn<10?'0':'')+mn+':'+(s<10?'0':'')+s;
  }
  update();
  setInterval(update,1000);
})();
