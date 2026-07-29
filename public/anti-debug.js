(function(){
  'use strict';
  var devtools = /./;
  devtools.toString = function(){
    return 'devtools-detected';
  };
  setInterval(function(){
    if(devtools.toString() !== 'devtools-detected'){
      document.body.style.opacity = '0.3';
      document.body.style.transition = 'opacity 0.3s';
    }
  }, 1000);
  if(window.outerWidth - window.innerWidth > 160){
    document.body.style.opacity = '0.3';
  }
})();
