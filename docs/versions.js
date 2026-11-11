/* Version switcher shared by the illustrated pages. Add a line here when a page is revised. */
(function(){
  var V={
    design:[
      {v:3,date:"2026-11-11",file:"design.html",note:"first code in; lobby and SIPs settled"},
      {v:2,date:"2026-11-11",file:"history/design-v2.html",note:"after design review 1"},
      {v:1,date:"2026-11-11",file:"history/design-v1.html",note:"first draft"}
    ],
    overview:[
      {v:2,date:"2026-11-11",file:"gazpacho-overview.html",note:"after design review 1"},
      {v:1,date:"2026-11-11",file:"history/overview-v1.html",note:"first version"}
    ]
  };
  var s=document.currentScript,doc=s.getAttribute("data-doc"),cur=+s.getAttribute("data-v"),root=s.getAttribute("data-root")||"";
  var list=V[doc]||[],latest=list[0]||{v:cur};
  var bar=document.createElement("div");
  bar.style.cssText="position:sticky;top:0;z-index:9;display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:center;padding:7px 12px;font:14px system-ui,Segoe UI,sans-serif;background:var(--card,#fff);color:var(--ink,#222);border-bottom:1px solid var(--line,#ddd)";
  var lab=document.createElement("span");lab.textContent="Version";
  var sel=document.createElement("select");sel.style.cssText="font:inherit;padding:3px 6px;border-radius:6px";
  list.forEach(function(x){var o=document.createElement("option");o.value=root+x.file;o.textContent="v"+x.v+" · "+x.date+" · "+x.note+(x.v===latest.v?" (latest)":"");if(x.v===cur)o.selected=true;sel.appendChild(o);});
  sel.onchange=function(){location.href=sel.value;};
  bar.appendChild(lab);bar.appendChild(sel);
  if(cur!==latest.v){var w=document.createElement("a");w.href=root+latest.file;w.textContent="You are viewing an older version. Go to the latest.";w.style.cssText="color:var(--tomato,#c00);font-weight:700";bar.appendChild(w);}
  document.body.insertBefore(bar,document.body.firstChild);
})();
