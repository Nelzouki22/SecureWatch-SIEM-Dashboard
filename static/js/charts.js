(function(){
  if(typeof Chart === "undefined") return;
  var D = window.SW_DATA || {};
  var dark = document.documentElement.getAttribute('data-theme') === 'dark';
  var grid = dark ? 'rgba(255,255,255,.1)' : 'rgba(0,0,0,.08)';
  var tick = dark ? '#cbd5e1' : '#64748b';
  var sevColors = {
    'Information':'#0ea5e9','Warning':'#f59e0b','Medium':'#a855f7',
    'High':'#ef4444','Critical':'#111827'
  };
  
  function mk(id, type, data, opts) {
    var el = document.getElementById(id);
    if(!el) return;
    new Chart(el, {
      type: type, data: data,
      options: Object.assign({
        responsive: true, maintainAspectRatio: false,
        plugins: {legend: {labels: {color: tick}}},
        scales: (type==='pie'||type==='doughnut') ? {} : {
          x: {ticks: {color: tick}, grid: {color: grid}},
          y: {ticks: {color: tick}, grid: {color: grid}}
        }
      }, opts || {})
    });
  }
  
  if(D.severity) mk('sevChart','bar',{
    labels: D.severity.labels,
    datasets: [{label:'Events', data: D.severity.values,
                backgroundColor: D.severity.labels.map(l=>sevColors[l]||'#64748b'),
                borderRadius: 6}]
  },{plugins:{legend:{display:false}}});
  
  if(D.day) mk('dayChart','line',{
    labels: D.day.labels,
    datasets: [{label:'Events', data: D.day.values,
                borderColor:'#0d6efd', backgroundColor:'rgba(13,110,253,.15)',
                fill:true, tension:.35}]
  },{plugins:{legend:{display:false}}});
  
  if(D.ips) mk('ipChart','bar',{
    labels: D.ips.labels,
    datasets: [{label:'Count', data: D.ips.values,
                backgroundColor:'#0ea5e9', borderRadius: 6}]
  },{indexAxis:'y', plugins:{legend:{display:false}}});
  
  if(D.users) mk('userChart','bar',{
    labels: D.users.labels,
    datasets: [{label:'Events', data: D.users.values,
                backgroundColor:'#22c55e', borderRadius: 6}]
  },{indexAxis:'y', plugins:{legend:{display:false}}});
  
  if(D.inc) mk('incChart','doughnut',{
    labels: D.inc.labels,
    datasets: [{data: D.inc.values,
                backgroundColor:['#ef4444','#f59e0b','#22c55e','#64748b','#0ea5e9']}]
  });
  
  if(D.severity) mk('distChart','pie',{
    labels: D.severity.labels,
    datasets: [{data: D.severity.values,
                backgroundColor: D.severity.labels.map(l=>sevColors[l]||'#64748b')}]
  });
  
  var sg = document.getElementById('score-gauge');
  if(sg && D.score !== undefined) {
    var pct = D.score;
    var col = pct >= 70 ? '#22c55e' : pct >= 40 ? '#f59e0b' : '#ef4444';
    new Chart(sg, {
      type: 'doughnut',
      data: {datasets: [{data: [pct, 100-pct],
                         backgroundColor: [col, dark?'#1f2735':'#e5e7eb'],
                         cutout: '75%'}]},
      options: {plugins: {legend:{display:false}, tooltip:{enabled:false}},
                rotation: -90, circumference: 180}
    });
  }
})();