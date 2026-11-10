"use strict";
// Agency (reseller) pages. Loaded by index.html after login; uses its helpers (h, t, call, post,
// modal, field, toast, fmtB, fmtDate, expiryEditor, infoModal, AS, go, render, ...).
(function(){
const TX={
 fa:{frozen:"اکانت‌ها متوقف",freeze:"توقف اکانت‌ها",unfreeze:"فعال‌سازی اکانت‌ها",freezeq:"همه‌ی اکانت‌های این نماینده (و زیرنماینده‌هایش) قطع و غیرفعال شود؟ خودش نمی‌تواند فعالشان کند.",unfreezeq:"اکانت‌های این نماینده دوباره فعال شود؟",frozenmsg:"همه‌ی اکانت‌های شما توسط مدیریت متوقف شده است. برای فعال‌سازی، حساب خود را تسویه کنید.",wallet:"کیف پول",customers:"مشتریان",subagents:"زیرنماینده‌ها",reports:"گزارش‌ها",profile:"پروفایل",agents:"نمایندگان",agency:"فروش و نمایندگی",
  balance:"موجودی",credit:"سقف اعتبار",sell:"فروش اکانت",renew:"تمدید",plan:"پلن",custom:"دلخواه",price:"قیمت",services:"سرویس‌ها",customer:"مشتری",nocust:"— بدون مشتری —",
  gb:"حجم (گیگ)",days:"روز",hours:"ساعت",devices:"دستگاه همزمان",note:"یادداشت",created:"ساخته شد",fresh:"شروع دوره جدید (مصرف صفر شود و حجم = حجم پلن)",
  quote:"هزینه",willpay:"از کیف پول کم می‌شود",after:"موجودی بعد",newagent:"نماینده جدید",parent:"والد",admin:"مدیر",brand:"نام تجاری",title:"عنوان نمایندگی",
  phone:"تلفن",tgchat:"آیدی عددی تلگرام (برای اعلان‌ها)",expiry:"انقضای نمایندگی",perms:"دسترسی‌ها",limits:"محدودیت‌ها",pricing:"قیمت‌ها",zero:"۰ = بدون محدودیت",
  inherit:"خالی/۰ = همان قیمت والد",api:"API",allowip:"IPهای مجاز (با کاما؛ خالی = همه)",rate:"درخواست در دقیقه (۰ = ۱۲۰)",newpass:"رمز جدید (خالی = بدون تغییر)",
  topup:"شارژ",deduct:"کسر",amount:"مبلغ",ban:"مسدود",unban:"رفع مسدودی",loginas:"ورود به پنل",move:"انتقال",ledger:"گردش حساب",status:"وضعیت",accts:"اکانت",
  sales30:"فروش ۳۰ روز",lastsale:"آخرین فروش",level:"سطح",search:"جستجو…",kind:"نوع",acct:"اکانت",by:"توسط",time:"زمان",csv:"خروجی اکسل (CSV)",
  today:"امروز",yesterday:"دیروز",d7:"۷ روز اخیر",d30:"۳۰ روز اخیر",thism:"این ماه",lastm:"ماه قبل",d90:"۹۰ روز اخیر",alltime:"از ابتدا",
  byday:"روزانه",byweek:"هفتگی",bymonth:"ماهانه",newsales:"فروش جدید",renews:"تمدید/افزایش",revenue:"درآمد",paid:"پرداختی",profit:"سود از زیرمجموعه",refunds:"بازگشت وجه",topups:"شارژها",
  period:"بازه",protos:"به تفکیک پروتکل",plans:"پلن‌ها",inactive:"نمایندگان بی‌فعالیت",debtors:"بدهکاران",top:"برترین نمایندگان",count:"تعداد",
  rules:"قوانین و قیمت پایه",requests:"درخواست‌ها",activity:"فعالیت‌ها",apilog:"لاگ API",approve:"تأیید",reject:"رد",pending:"در انتظار",approved:"تأیید شد",rejected:"رد شد",
  currency:"واحد پول",baseprices:"قیمت پایه برای نمایندگان سطح اول",maxlevels:"حداکثر سطح نمایندگی",refund:"بازگشت وجه هنگام حذف اکانت",
  rnone:"بدون بازگشت وجه",rwindow:"بازگشت کامل اگر تازه و کم‌مصرف باشد",rprorated:"بازگشت به نسبت باقیمانده (حجم/زمان)",rhours:"تا چند ساعت پس از ساخت",rused:"حداکثر مصرف ٪",rpct:"درصد بازگشت",
  lowbal:"هشدار وقتی موجودی کمتر از",notifysale:"اطلاع هر فروش در تلگرام مدیر",planname:"نام پلن",renewprice:"قیمت تمدید (۰ = همان قیمت)",order:"ترتیب",enabled:"فعال",
  keys:"کلیدهای API",newkey:"کلید جدید",keyonce:"این کلید فقط یک بار نمایش داده می‌شود؛ همین حالا کپی کنید:",lastuse:"آخرین استفاده",
  chpw:"تغییر رمز",oldpw:"رمز فعلی",newpw6:"رمز جدید (حداقل ۶)",myprices:"قیمت‌های شما",back:"بازگشت به پنل مدیر",watching:"در حال مشاهده‌ی پنل نمایندگی",
  expiring:"در آستانه‌ی انقضا (۳ روز)",lowq:"حجم رو به اتمام",recent:"آخرین تراکنش‌ها",ownacc:"اکانت‌های من",subacc:"اکانت‌های زیرمجموعه",
  totalbal:"جمع موجودی‌ها",totaldebt:"جمع بدهی‌ها",agentaccts:"اکانت‌های نمایندگان",tousername:"نام کاربری نمایندگی مقصد",sentapprove:"برای تأیید مدیر ارسال شد",
  setcust:"تعیین مشتری",name:"نام",tgid:"تلگرام",acctlist:"اکانت‌ها",apidoc:"راهنمای API",formula:"قیمت فروش دلخواه = حجم × قیمت هر گیگ + روز × قیمت هر روز. اگر حجم و روز دقیقاً با یک پلن برابر باشد (مثل فروش ربات)، قیمت همان پلن حساب می‌شود. حجم نامحدود فقط هزینه‌ی روز دارد مگر با پلن.",
  cascade:"وقتی زیرنماینده می‌فروشد، از کیف پول او قیمت خودش و از کیف پول شما قیمت شما کم می‌شود؛ تفاوت سود شماست. شارژ کیف پول زیرنماینده از موجودی شما کم نمی‌شود (پولش را خودتان از او می‌گیرید).",
  plansell:"قیمت پلن",planrenew:"تمدید پلن",inactivedays:"بی‌فعالیت بیش از (روز)",allagents:"همه",self:"خودم",impossible:"امکان‌پذیر نیست",
  kinds:{topup:"شارژ",deduct:"کسر",transfer_in:"انتقال ورودی",transfer_out:"انتقال خروجی",sale:"فروش",renew:"تمدید",addgb:"افزایش حجم",adddays:"افزایش زمان",reset:"ریست حجم",refund:"بازگشت وجه",reversal:"برگشت (انجام نشد)",commission:"کمیسیون",adjust:"اصلاح"},
  st:{active:"فعال",disabled:"غیرفعال",banned:"مسدود",expired:"منقضی"},
  P:{create:"فروش اکانت جدید",renew:"تمدید و افزایش حجم/زمان",reset:"ریست حجم (با هزینه)",delete:"حذف اکانت (بازگشت وجه طبق قوانین)",suspend:"فعال/غیرفعال کردن اکانت",edit:"ویرایش (رمز، دستگاه، سرویس)",unlimited:"فروش نامحدود",bulk:"عملیات گروهی",subAgents:"ساخت زیرنماینده",transfer:"انتقال اکانت",api:"API اختصاصی"},
  L:{maxCustomers:"حداکثر تعداد اکانت",maxActive:"حداکثر اکانت فعال",maxDailyCreates:"حداکثر ساخت در روز",maxSoldGB:"سقف کل حجم فروش (گیگ)",maxDays:"حداکثر روز هر فروش",maxGB:"حداکثر حجم هر اکانت (گیگ)",maxDevices:"حداکثر دستگاه هر اکانت",maxSubAgents:"حداکثر زیرنماینده",creditLimit:"سقف اعتبار (بدهی مجاز)"},
  PR:{perGB:"هر گیگ (فروش)",perDay:"هر روز (فروش)",addGB:"هر گیگ (افزایش/تمدید)",addDay:"هر روز (افزایش/تمدید)",discount:"تخفیف ٪"}},
 en:{frozen:"accounts suspended",freeze:"Suspend accounts",unfreeze:"Resume accounts",freezeq:"Disconnect and suspend every account of this agency (and its sub-agents)? The agency cannot switch them back on.",unfreezeq:"Resume this agency's accounts?",frozenmsg:"All your accounts are suspended by the management. Settle your account to resume.",wallet:"Wallet",customers:"Customers",subagents:"Sub-agents",reports:"Reports",profile:"Profile",agents:"Agencies",agency:"Sales & agency",
  balance:"Balance",credit:"Credit limit",sell:"Sell account",renew:"Renew",plan:"Plan",custom:"Custom",price:"Price",services:"Services",customer:"Customer",nocust:"— no customer —",
  gb:"Quota (GB)",days:"Days",hours:"Hours",devices:"Devices",note:"Note",created:"Created",fresh:"New period (usage back to 0, quota = plan quota)",
  quote:"Cost",willpay:"taken from the wallet",after:"Balance after",newagent:"New agency",parent:"Parent",admin:"Admin",brand:"Brand",title:"Title",
  phone:"Phone",tgchat:"Telegram chat id (notices)",expiry:"Agency expiry",perms:"Permissions",limits:"Limits",pricing:"Prices",zero:"0 = no limit",
  inherit:"empty/0 = the parent's price",api:"API",allowip:"Allowed IPs (comma; empty = any)",rate:"Requests per minute (0 = 120)",newpass:"New password (empty = keep)",
  topup:"Top up",deduct:"Deduct",amount:"Amount",ban:"Ban",unban:"Unban",loginas:"Open panel",move:"Move",ledger:"Ledger",status:"Status",accts:"accounts",
  sales30:"Sales 30d",lastsale:"Last sale",level:"Level",search:"Search…",kind:"Kind",acct:"Account",by:"By",time:"Time",csv:"Export (CSV)",
  today:"Today",yesterday:"Yesterday",d7:"Last 7 days",d30:"Last 30 days",thism:"This month",lastm:"Last month",d90:"Last 90 days",alltime:"All time",
  byday:"Daily",byweek:"Weekly",bymonth:"Monthly",newsales:"New sales",renews:"Renewals",revenue:"Revenue",paid:"Paid",profit:"Profit from sub-agents",refunds:"Refunds",topups:"Top-ups",
  period:"Period",protos:"By protocol",plans:"Plans",inactive:"Inactive agencies",debtors:"In debt",top:"Top agencies",count:"Count",
  rules:"Rules & base prices",requests:"Requests",activity:"Activity",apilog:"API log",approve:"Approve",reject:"Reject",pending:"pending",approved:"approved",rejected:"rejected",
  currency:"Currency",baseprices:"Base prices for top-level agencies",maxlevels:"Agency levels",refund:"Refund when an account is deleted",
  rnone:"No refund",rwindow:"Full refund when new and barely used",rprorated:"Refund what is left (quota/time)",rhours:"Within hours of creation",rused:"Max usage %",rpct:"Refund percent",
  lowbal:"Warn when a balance is below",notifysale:"Tell the admin about every sale on Telegram",planname:"Plan name",renewprice:"Renewal price (0 = price)",order:"Order",enabled:"Enabled",
  keys:"API keys",newkey:"New key",keyonce:"This key is shown only once; copy it now:",lastuse:"Last used",
  chpw:"Change password",oldpw:"Current password",newpw6:"New password (6+)",myprices:"Your prices",back:"Back to the admin panel",watching:"Viewing the panel of agency",
  expiring:"Expiring within 3 days",lowq:"Almost out of quota",recent:"Recent transactions",ownacc:"My accounts",subacc:"Sub-agents' accounts",
  totalbal:"Total balances",totaldebt:"Total debt",agentaccts:"Agencies' accounts",tousername:"Receiving agency's username",sentapprove:"Sent to the admin for approval",
  setcust:"Set customer",name:"Name",tgid:"Telegram",acctlist:"Accounts",apidoc:"API guide",formula:"Custom sale price = GB × price per GB + days × price per day. When quota and days equal a plan (like the bot's sales), the plan's price applies. Unlimited quota costs only the days unless sold as a plan.",
  cascade:"When a sub-agent sells, its wallet pays its price and yours pays your price; the difference is your profit. Topping up a sub-agent does not take from your wallet (you collect that money yourself).",
  plansell:"Plan price",planrenew:"Plan renewal",inactivedays:"Inactive for more than (days)",allagents:"All",self:"Myself",impossible:"Not possible",
  kinds:{topup:"top-up",deduct:"deduct",transfer_in:"transfer in",transfer_out:"transfer out",sale:"sale",renew:"renewal",addgb:"added quota",adddays:"added time",reset:"reset",refund:"refund",reversal:"reversal",commission:"commission",adjust:"adjust"},
  st:{active:"active",disabled:"disabled",banned:"banned",expired:"expired"},
  P:{create:"Sell new accounts",renew:"Renew / add quota and time",reset:"Reset usage (charged)",delete:"Delete accounts (refund by the rules)",suspend:"Enable / disable accounts",edit:"Edit (password, devices, services)",unlimited:"Sell unlimited",bulk:"Bulk actions",subAgents:"Create sub-agents",transfer:"Move accounts",api:"Personal API"},
  L:{maxCustomers:"Max accounts",maxActive:"Max active accounts",maxDailyCreates:"Max new accounts per day",maxSoldGB:"Total GB sold cap",maxDays:"Max days per sale",maxGB:"Max GB per account",maxDevices:"Max devices per account",maxSubAgents:"Max sub-agents",creditLimit:"Credit limit (allowed debt)"},
  PR:{perGB:"Per GB (sale)",perDay:"Per day (sale)",addGB:"Per GB (add/renew)",addDay:"Per day (add/renew)",discount:"Discount %"}}
};
for(const l of ["fa","en"])for(const k in TX[l])if(typeof TX[l][k]==="string")T[l][k]=TX[l][k];
const X=k=>(TX[lang]||TX.en)[k];
const ta=k=>t(k);
const kindName=k=>X("kinds")[k]||k;
const fnum=n=>(+n||0).toLocaleString(lang==="fa"?"fa-IR":"en-US");
const money=n=>lang==="fa"?"\u2067"+fnum(n)+" "+(ME.currency||"")+"\u2069":fnum(n)+" "+(ME.currency||"");
const put=(el,...kids)=>el.replaceChildren(...kids.flat(9).filter(k=>k!=null&&k!==false));
const color=n=>n<0?"var(--er)":n>0?"var(--ok)":"";
const stat=(ic,col,label,val,sub)=>h("div",{class:"card dc",style:"--c:"+col},h("div",{class:"dh"},h("span",{class:"di"},ic),h("span",{class:"dl"},label)),h("div",{class:"dv num"},val),sub?h("div",{class:"mu",style:"font-size:11px;margin-top:4px"},sub):null);
const tbl=(heads,rows)=>h("div",{class:"card sc",style:"margin-bottom:12px"},rows.length?h("table",{},h("tr",{},heads.map(x=>h("th",{},x))),rows):h("div",{class:"mu"},t("none")));
const sec=(title,...kids)=>h("div",{class:"card",style:"margin-bottom:12px"},h("h3",{style:"margin-top:0"},title),...kids);
const num0=(v,attrs)=>h("input",{type:"number",step:"any",min:0,value:v||"",placeholder:"0",...(attrs||{})});
const q=o=>new URLSearchParams(Object.fromEntries(Object.entries(o).filter(([k,v])=>v!==""&&v!=null))).toString();
let PLANS=[],AGENTS=[];
async function loadPlans(){PLANS=await call("panel/agency/plans")||[];return PLANS}
async function loadAgents(){if(ME.role==="agent"&&!ME.agent.perms.subAgents){AGENTS=[];AGN={};return}
 AGENTS=await call("panel/agency/agents")||[];AGN={};AGENTS.forEach(a=>AGN[a.id]=a.username);return AGENTS}
async function refreshMe(){try{const j=await call("panel/agency/whoami");ME=j;const e=document.getElementById("agbal");if(e)e.replaceWith(balBox())}catch(e){}}
function balBox(){return h("div",{id:"agbal",style:"margin:-8px 10px 14px;padding:8px 10px;border-radius:10px;background:rgba(255,255,255,.08);color:#fff"},
 h("div",{style:"font-size:11px;opacity:.75"},X("balance")),h("b",{class:"num",style:"color:"+(ME.balance<0?"#fca5a5":"#fff")},money(ME.balance)))}
function rangeOf(k){const now=Date.now(),D=864e5,p=cal.parts(now),sod=x=>{const d=new Date(x);d.setHours(0,0,0,0);return d.getTime()};
 switch(k){case"today":return[sod(now),0];case"yesterday":return[sod(now)-D,sod(now)-1];case"d7":return[now-7*D,0];case"d30":return[now-30*D,0];case"d90":return[now-90*D,0];
  case"thism":return[cal.ms(p.y,p.m,1,0,0),0];case"lastm":{const y=p.m===1?p.y-1:p.y,m=p.m===1?12:p.m-1;return[cal.ms(y,m,1,0,0),cal.ms(p.y,p.m,1,0,0)-1]}}return[0,0]}
const rangeSel=(v,on)=>h("select",{onchange:e=>on(e.target.value)},["today","yesterday","d7","d30","thism","lastm","d90","alltime"].map(k=>h("option",{value:k,selected:k===v},X(k))));
function agentSel(v,on,withAll){const o=[];if(withAll)o.push(["",X("allagents")]);if(ME.role==="agent")o.push([String(ME.agent.id),X("self")]);
 AGENTS.forEach(a=>o.push([String(a.id),"  ".repeat(Math.max(0,a.level-1-(ME.role==="agent"?ME.level:0)))+a.username+(a.brand?" ("+a.brand+")":"")]));
 return h("select",{onchange:e=>on(e.target.value)},o.map(([k,l])=>h("option",{value:k,selected:String(v)===k},l)))}
function copyBtn(txt){return h("button",{class:"btn",onclick:()=>{navigator.clipboard&&navigator.clipboard.writeText(txt);toast(t("copy"))}},t("copy"))}

/* ---------- selling ---------- */
function svcBoxes(sel){return (ME.services||[]).map(s=>[s,h("input",{type:"checkbox",checked:sel?sel.includes(s.id):true})])}
function svcField(boxes){return field(X("services"),h("div",{style:"flex:1"},boxes.map(([s,b])=>h("label",{style:"display:block;width:auto;color:inherit"},b," ",s.remark||s.protocol," ",h("span",{class:"tag"},s.protocol)))))}
function planSel(on,renew){return h("select",{onchange:e=>on(+e.target.value)},[h("option",{value:0},X("custom")),...PLANS.map(p=>h("option",{value:p.id},
 p.name+" — "+(p.gb?fnum(p.gb)+"GB":"∞")+" / "+(p.days?fnum(+(+p.days).toFixed(2))+(lang==="fa"?" روز":"d"):"∞")+" — "+money(renew?p.myRenew:p.myPrice)))])}
async function custOptions(){try{return await call("panel/agency/customers")}catch(e){return[]}}
async function sellModal(after){await loadPlans();const custs=await custOptions();
 const rnd="u"+Math.random().toString(36).slice(2,7);
 const f={user:h("input",{value:rnd,dir:"ltr"}),pass:h("input",{value:randpw(),dir:"ltr"}),gb:num0(10),days:num0(30),hours:num0(0),dev:num0(ME.agent.limits.maxDevices||1),
  cust:h("select",{},[h("option",{value:0},X("nocust")),...custs.map(c=>h("option",{value:c.id},c.name+(c.phone?" — "+c.phone:"")))]),note:h("input",{})};
 let plan=0;const boxes=svcBoxes();const cost=h("div",{class:"card",style:"background:rgba(99,102,241,.08);margin-top:8px"},"…");
 const cust=[field(X("gb"),f.gb),field(X("days"),f.days),field(X("hours"),f.hours)],custBox=h("div",{},cust);
 const ps=planSel(v=>{plan=v;const p=PLANS.find(x=>x.id===v);custBox.style.display=v?"none":"";if(p){if(p.devices)f.dev.value=p.devices;if(p.inbounds&&p.inbounds.length)boxes.forEach(([s,b])=>b.checked=p.inbounds.includes(s.id))}quote()});
 let qt;const quote=()=>{clearTimeout(qt);qt=setTimeout(async()=>{try{const r=await post("panel/agency/quote",{kind:"sale",plan,gb:+f.gb.value||0,days:+f.days.value||0,hours:+f.hours.value||0});
  put(cost,h("b",{},X("quote")+": "+money(r.price))," ",h("span",{class:"mu"},X("willpay")+" — "+X("after")+": "),h("b",{class:"num",style:"color:"+color(r.balance-r.price)},money(r.balance-r.price)))}catch(e){cost.textContent=e.message}},250)};
 [f.gb,f.days,f.hours].forEach(e=>e.addEventListener("input",quote));quote();
 const m=modal(X("sell"),h("div",{},field(t("user"),f.user),field(t("pass"),f.pass),field(X("plan"),ps),custBox,svcField(boxes),field(X("devices"),f.dev),
  custs.length?field(X("customer"),f.cust):null,field(t("comment"),f.note),cost,h("div",{class:"mu",style:"font-size:12px;margin-top:6px"},X("formula"))),[
  h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async e=>{const ids=boxes.filter(([s,b])=>b.checked).map(([s])=>s.id);if(!ids.length){toast(X("services"),1);return}
   e.target.disabled=true;try{const r=await post("panel/agency/sell",{username:f.user.value.trim(),password:f.pass.value.trim(),plan,gb:+f.gb.value||0,days:+f.days.value||0,hours:+f.hours.value||0,
    inbounds:ids,limitIp:+f.dev.value||0,customer:+f.cust.value||0,comment:f.note.value});
    m.remove();refreshMe();toast(X("created"));infoModal({email:r.username,username:r.username,password:r.password,inbounds:ids});after&&after()}catch(x){e.target.disabled=false}}},X("sell"))])}
async function renewModal(emails,after){await loadPlans();
 const f={gb:num0(0),days:num0(30),hours:num0(0),fresh:h("input",{type:"checkbox"})};let plan=0;
 const cost=h("div",{class:"card",style:"background:rgba(99,102,241,.08);margin-top:8px"},"…");
 const custBox=h("div",{},field(X("gb"),f.gb),field(X("days"),f.days),field(X("hours"),f.hours));
 const ps=planSel(v=>{plan=v;custBox.style.display=v?"none":"";quote()},true);
 let qt;const quote=()=>{clearTimeout(qt);qt=setTimeout(async()=>{const gb=+f.gb.value||0,d=(+f.days.value||0)+(+f.hours.value||0)/24;
  const kind=plan||(gb>0&&d>0)?"renew":gb>0?"addgb":"adddays";
  try{const r=await post("panel/agency/quote",{kind,plan,gb,days:+f.days.value||0,hours:+f.hours.value||0});const tot=r.price*emails.length;
   put(cost,h("b",{},X("quote")+": "+money(tot)),emails.length>1?h("span",{class:"mu"}," ("+emails.length+" × "+money(r.price)+")"):null," — ",h("span",{class:"mu"},X("after")+": "),h("b",{class:"num",style:"color:"+color(r.balance-tot)},money(r.balance-tot)))}catch(e){cost.textContent=e.message}},250)};
 [f.gb,f.days,f.hours].forEach(e=>e.addEventListener("input",quote));quote();
 const m=modal(X("renew")+" — "+(emails.length>1?emails.length+" "+X("accts"):emails[0]),h("div",{},field(X("plan"),ps),custBox,field("",h("label",{style:"width:auto;color:inherit"},f.fresh," ",X("fresh"))),cost),[
  h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async e=>{e.target.disabled=true;try{const r=await post("panel/agency/renew",{emails,plan,gb:+f.gb.value||0,days:+f.days.value||0,hours:+f.hours.value||0,fresh:f.fresh.checked});
   m.remove();refreshMe();toast(t("saved"));after&&after()}catch(x){e.target.disabled=false}}},X("renew"))])}
async function moveModal(emails,done){if(!AGENTS.length&&(ME.role==="admin"||ME.agent.perms.subAgents))await loadAgents();
 const opts=ME.role==="admin"?[["0",X("admin")]]:[];AGENTS.forEach(a=>opts.push([String(a.id),a.username+(a.brand?" ("+a.brand+")":"")]));
 const s=h("select",{},opts.map(([v,l])=>h("option",{value:v},l))),other=h("input",{dir:"ltr",placeholder:X("tousername")}),note=h("input",{});
 const m=modal(X("move")+" — "+emails.length+" "+X("accts"),h("div",{},opts.length?field(X("agents"),s):null,ME.role==="agent"?field(X("tousername"),other):null,ME.role==="agent"?field(X("note"),note):null),[
  h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async()=>{const body={emails,note:note.value};if(other.value.trim())body.to=other.value.trim();else body.owner=+s.value;
   const j=await api("panel/agency/accounts/move",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});toast(j.msg,!j.success);if(j.success){m.remove();done&&done()}}},X("move"))])}
async function custModal(emails,done){const custs=await custOptions();const s=h("select",{},[h("option",{value:0},X("nocust")),...custs.map(c=>h("option",{value:c.id},c.name))]);
 const m=modal(X("setcust"),field(X("customer"),s),[h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async()=>{await post("panel/agency/accounts/customer",{emails,customer:+s.value});toast(t("saved"));m.remove();done&&done()}},t("save"))])}
function agBulkCreate(after){(async()=>{await loadPlans();
 const f={prefix:h("input",{value:"u",dir:"ltr"}),count:num0(10),gb:num0(10),days:num0(30),hours:num0(0),dev:num0(ME.agent.limits.maxDevices||1)};let plan=0;const boxes=svcBoxes();
 const custBox=h("div",{},field(X("gb"),f.gb),field(X("days"),f.days),field(X("hours"),f.hours));
 const ps=planSel(v=>{plan=v;custBox.style.display=v?"none":""});
 const m=modal(t("bulkc"),h("div",{},field(t("prefix"),f.prefix),field(t("count"),f.count),field(X("plan"),ps),custBox,svcField(boxes),field(X("devices"),f.dev)),[
  h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async e=>{const ids=boxes.filter(([s,b])=>b.checked).map(([s])=>s.id);if(!ids.length){toast(X("services"),1);return}e.target.disabled=true;
   const j=await api("panel/ui/bulkCreate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({prefix:f.prefix.value,count:+f.count.value,inbounds:ids,plan,gb:+f.gb.value||0,days:+f.days.value||0,hours:+f.hours.value||0,limitIp:+f.dev.value||0,singleProto:true})});
   e.target.disabled=false;if(!j.success&&!(j.obj&&j.obj.length)){toast(j.msg,1);return}if(!j.success)toast(j.msg,1);m.remove();refreshMe();
   const txt=(j.obj||[]).map(x=>x.User+"\t"+x.Pass).join("\n");const m2=modal(t("created")+" ("+(j.obj||[]).length+")",h("pre",{},txt),[copyBtn(txt),h("button",{class:"btn p",onclick:()=>{m2.remove();after&&after()}},"OK")])}},t("save"))])})()}

/* ---------- agents (admin: all; reseller: its sub-agents) ---------- */
async function enter(a){await post("panel/agency/agents/"+a.id+"/login");location.hash="#/accounts";location.reload()}
async function pAgents(c){await Promise.all([loadAgents(),loadPlans()]);let qs="";
 const body=h("div");
 const draw=()=>{const list=AGENTS.filter(a=>!qs||(a.username+" "+(a.brand||"")+" "+(a.phone||"")+" "+(a.title||"")).toLowerCase().includes(qs));
  const kids={};list.forEach(a=>{(kids[a.parent]=kids[a.parent]||[]).push(a)});const ids=new Set(list.map(a=>a.id)),ordered=[];
  const walk=(a,d)=>{ordered.push([a,d]);(kids[a.id]||[]).forEach(k=>walk(k,d+1))};list.filter(a=>!ids.has(a.parent)).forEach(a=>walk(a,0));
  let sum=0,debt=0;AGENTS.forEach(a=>{sum+=a.balance;if(a.balance<0)debt+=a.balance});
  put(body,h("div",{class:"dg"},stat("🤝","#6366f1",X("agents"),fnum(AGENTS.length)),stat("💰","#10b981",X("totalbal"),money(sum)),stat("📉","#ef4444",X("totaldebt"),money(debt))),
   tbl([t("name"),X("status"),X("balance"),X("accts"),t("online"),X("sales30"),X("lastsale"),""],ordered.map(([a,d])=>h("tr",{},
    h("td",{},h("div",{style:"padding-inline-start:"+(d*18)+"px"},d?h("span",{class:"mu"},"↳ "):null,ME.role==="admin"?h("b",{style:"cursor:pointer;color:var(--pr)",title:X("loginas"),onclick:()=>enter(a)},a.username):h("b",{},a.username),a.brand?h("span",{class:"mu"}," "+a.brand):null),
     h("div",{class:"mu",style:"font-size:11px;padding-inline-start:"+(d*18)+"px"},X("level")+" "+fnum(a.level)+(a.parentName?" · "+X("parent")+": "+a.parentName:"")+(a.phone?" · "+a.phone:""))),
    h("td",{},h("span",{class:"pill "+(a.status==="active"?"active":a.status==="disabled"?"disabled":"expired")},X("st")[a.status]||a.status),a.frozen?h("div",{},h("span",{class:"pill expired",title:a.frozenNote||""},"⛔ "+X("frozen"))):null,a.banReason?h("div",{class:"mu",style:"font-size:11px"},a.banReason):null),
    h("td",{},h("b",{class:"num",style:"color:"+color(a.balance)},money(a.balance))),
    h("td",{},h("span",{class:"num"},fnum(a.active)+" / "+fnum(a.accounts)),h("div",{class:"mu num",style:"font-size:11px"},fmtB(a.used))),h("td",{},fnum(a.online)),
    h("td",{},h("div",{class:"num"},fnum(a.salesMonth)),h("div",{class:"mu num",style:"font-size:11px"},money(a.paidMonth))),
    h("td",{class:"mu"},a.lastSale?ago(a.lastSale):t("never")),
    h("td",{class:"ops"},ib("✎",t("edit"),()=>agentModal(a,reload)),ib("💰",X("wallet"),()=>walletModal(a,reload)),ib("📒",X("ledger"),()=>ledgerModal(a)),
     ib("🔎",t("accounts"),()=>{AS.owner=String(a.id);AS.page=1;AS.q="";AS.status="";go("accounts")}),
     a.status==="banned"?ib("✅",X("unban"),async()=>{await post("panel/agency/agents/"+a.id+"/ban",{until:0});reload()}):ib("⛔",X("ban"),()=>banModal(a,reload)),
     a.frozen?ib("▶",X("unfreeze"),async()=>{if(!confirm(X("unfreezeq")+"\n"+a.username))return;await post("panel/agency/agents/"+a.id+"/freeze",{on:false});toast(t("saved"));reload()})
      :ib("⏸",X("freeze"),async()=>{const note=prompt(X("freezeq")+"\n"+a.username+"\n\n"+X("note")+":","");if(note===null)return;await post("panel/agency/agents/"+a.id+"/freeze",{on:true,note});toast(t("saved"));reload()},"d"),
     ME.role==="admin"?ib("👁",X("loginas"),()=>enter(a)):null,
     ME.role==="admin"?ib("↪",X("move"),()=>agentMoveModal(a,reload)):null,
     ib("🗑",t("del"),async()=>{if(!confirm(t("confirm")+"\n"+a.username))return;await post("panel/agency/agents/"+a.id+"/delete");reload()},"d"))))))};
 const reload=async()=>{await loadAgents();draw()};
 const search=h("input",{placeholder:X("search"),style:"max-width:220px",oninput:e=>{qs=e.target.value.trim().toLowerCase();draw()}});
 put(c,h("div",{class:"top"},h("h2",{},t(ME.role==="admin"?"agents":"subagents")),h("button",{class:"btn p",onclick:()=>agentModal(null,reload)},"+ "+X("newagent")),search),
  ME.role==="agent"?h("div",{class:"card mu",style:"margin-bottom:12px;font-size:12.5px"},X("cascade")):null,body);
 draw()}
function agentModal(a,after){const isNew=!a;a=a||{username:"",parent:ME.role==="agent"?ME.agent.id:0,enable:true,expiry:0,brand:"",title:"",phone:"",tgChat:"",note:"",
  perms:{create:true,renew:true,reset:false,delete:true,suspend:true,edit:true,unlimited:false,bulk:false,subAgents:false,transfer:false,api:false},
  limits:{inbounds:[]},pricing:{plans:{}},apiAllow:[],apiRate:0};
 const L=a.limits||{},P=a.pricing||{},pp=P.plans||{};
 const f={user:h("input",{value:a.username,dir:"ltr"}),pass:h("input",{value:isNew?randpw():"",placeholder:isNew?"":X("newpass"),dir:"ltr"}),en:h("input",{type:"checkbox",class:"sw",checked:a.enable}),
  brand:h("input",{value:a.brand||""}),title:h("input",{value:a.title||""}),phone:h("input",{value:a.phone||"",dir:"ltr"}),tg:h("input",{value:a.tgChat||"",dir:"ltr"}),note:h("textarea",{rows:2,style:"flex:1"},a.note||""),
  allow:h("input",{value:(a.apiAllow||[]).join(", "),dir:"ltr"}),rate:num0(a.apiRate)};
 const exp=expiryEditor(a.expiry||0);
 const parents=[...(ME.role==="admin"?[[0,X("admin")]]:[]),...AGENTS.filter(x=>x.perms.subAgents&&x.id!==a.id).map(x=>[x.id,x.username])];
 const par=h("select",{disabled:!isNew||ME.role!=="admin"},parents.map(([v,l])=>h("option",{value:v,selected:v===a.parent},l)));
 const mine=ME.role==="agent"?ME.agent.perms:null;
 const perms=Object.keys(X("P")).map(k=>[k,h("input",{type:"checkbox",checked:!!a.perms[k],disabled:mine&&!mine[k]})]);
 const lim=Object.keys(X("L")).map(k=>[k,num0(L[k])]);
 const svc=(ME.services||[]).map(s=>[s,h("input",{type:"checkbox",checked:(L.inbounds||[]).includes(s.id)})]);
 const eff=a.eff||{};
 const pr=Object.keys(X("PR")).map(k=>[k,num0(P[k],{placeholder:k!=="discount"&&eff[k]?fnum(eff[k]):"0"})]);
 const plans=PLANS.map(p=>[p,num0((pp[p.id]||{}).sell,{placeholder:fnum(p.myPrice),style:"width:110px"}),num0((pp[p.id]||{}).renew,{placeholder:fnum(p.myRenew),style:"width:110px"})]);
 const grid=kids=>h("div",{style:"display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:0 14px"},kids);
 const m=modal(isNew?X("newagent"):t("edit")+" — "+a.username,h("div",{},
  field(t("user"),f.user),field(isNew?t("pass"):X("newpass"),f.pass),parents.length>1||ME.role==="admin"?field(X("parent"),par):null,field(t("enable"),f.en),field(X("expiry"),exp.el),
  field(X("brand"),f.brand),field(X("title"),f.title),field(X("phone"),f.phone),field(X("tgchat"),f.tg),field(X("note"),f.note),
  h("h4",{},X("perms")),grid(perms.map(([k,b])=>h("label",{style:"display:block;width:auto;color:inherit;margin:3px 0"},b," ",X("P")[k]))),
  h("h4",{},X("limits")+" ",h("span",{class:"mu",style:"font-weight:400;font-size:12px"},X("zero"))),grid(lim.map(([k,e])=>field(X("L")[k],e))),
  field(X("services"),h("div",{style:"flex:1"},h("div",{class:"mu",style:"font-size:12px"},lang==="fa"?"هیچ‌کدام = همه‌ی سرویس‌های مجاز والد":"none = everything the parent may sell"),svc.map(([s,b])=>h("label",{style:"display:inline-block;width:auto;color:inherit;margin-inline-end:10px"},b," ",s.remark||s.protocol)))),
  h("h4",{},X("pricing")+" ",h("span",{class:"mu",style:"font-weight:400;font-size:12px"},X("inherit"))),grid(pr.map(([k,e])=>field(X("PR")[k],e))),
  PLANS.length?h("table",{},h("tr",{},h("th",{},X("plan")),h("th",{},X("plansell")),h("th",{},X("planrenew"))),plans.map(([p,s,r])=>h("tr",{},h("td",{},p.name),h("td",{},s),h("td",{},r)))):null,
  h("h4",{},X("api")),field(X("allowip"),f.allow),field(X("rate"),f.rate)),[
  h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async()=>{
   const body={id:a.id||0,parent:+par.value||0,username:f.user.value.trim(),password:f.pass.value,enable:f.en.checked,expiry:exp.value(),brand:f.brand.value,title:f.title.value,phone:f.phone.value,tgChat:f.tg.value,note:f.note.value,
    perms:Object.fromEntries(perms.map(([k,b])=>[k,b.checked])),limits:Object.fromEntries(lim.map(([k,e])=>[k,+e.value||0])),
    pricing:Object.fromEntries(pr.map(([k,e])=>[k,+e.value||0])),apiAllow:f.allow.value.split(/[,\s]+/).filter(Boolean),apiRate:+f.rate.value||0};
   body.limits.inbounds=svc.filter(([s,b])=>b.checked).map(([s])=>s.id);
   body.pricing.plans={};plans.forEach(([p,s,r])=>{if(+s.value||+r.value)body.pricing.plans[p.id]={sell:+s.value||0,renew:+r.value||0}});
   await post("panel/agency/agents/save",body);toast(t("saved"));m.remove();after&&after()}},t("save"))]);
 m.querySelector(".card").style.width="min(760px,100%)"}
function walletModal(a,after){let op="topup";const amt=num0(""),note=h("input",{});
 const r=k=>h("label",{style:"width:auto;color:inherit;margin-inline-end:14px"},h("input",{type:"radio",name:"wop",checked:k===op,onchange:()=>op=k})," ",X(k));
 const m=modal(X("wallet")+" — "+a.username,h("div",{},h("div",{style:"margin-bottom:10px"},X("balance")+": ",h("b",{class:"num",style:"color:"+color(a.balance)},money(a.balance))),
  field("",h("div",{},r("topup"),r("deduct"))),field(X("amount"),amt),field(X("note"),note),ME.role==="agent"?h("div",{class:"mu",style:"font-size:12px"},X("cascade")):null),[
  h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async()=>{if(!(+amt.value>0)){toast(X("amount"),1);return}await post("panel/agency/agents/"+a.id+"/wallet",{op,amount:Math.round(+amt.value),note:note.value});toast(t("saved"));m.remove();after&&after()}},t("save"))])}
function banModal(a,after){const sel=h("select",{},[[36e5,"1h"],[864e5,"1d"],[7*864e5,"7d"],[30*864e5,"30d"],[-1,"∞"]].map(([v,l])=>h("option",{value:v},l))),why=h("input",{});
 const m=modal(X("ban")+" — "+a.username,h("div",{},field(t("time"),sel),field(X("note"),why)),[h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn d",onclick:async()=>{const v=+sel.value;await post("panel/agency/agents/"+a.id+"/ban",{until:v<0?-1:Date.now()+v,reason:why.value});toast(t("saved"));m.remove();after&&after()}},X("ban"))])}
function agentMoveModal(a,after){const s=h("select",{},[[0,X("admin")],...AGENTS.filter(x=>x.id!==a.id&&x.perms.subAgents).map(x=>[x.id,x.username])].map(([v,l])=>h("option",{value:v,selected:v===a.parent},l)));
 const m=modal(X("move")+" — "+a.username,field(X("parent"),s),[h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
  h("button",{class:"btn p",onclick:async()=>{await post("panel/agency/agents/"+a.id+"/move",{parent:+s.value});toast(t("saved"));m.remove();after&&after()}},t("save"))])}
function ledgerTable(items,names){return tbl([X("time"),X("kind"),X("amount"),X("balance"),X("acct"),"",X("by"),X("note")],items.map(e=>h("tr",{},
 h("td",{class:"mu"},fmtDate(e.t)),h("td",{},h("span",{class:"tag"},kindName(e.kind)),names&&ME.role==="admin"?h("div",{class:"mu",style:"font-size:11px"},names[e.agent]||("#"+e.agent)):null),
 h("td",{},h("b",{class:"num",style:"color:"+color(e.amt)},(e.amt>0?"+":"")+fnum(e.amt))),h("td",{class:"num"},fnum(e.bal)),h("td",{},e.acct||""),
 h("td",{class:"mu num",style:"font-size:11px"},[e.gb?fnum(+e.gb.toFixed(2))+"GB":"",e.days?fnum(+e.days.toFixed(2))+(lang==="fa"?"روز":"d"):"",e.profit?"+"+fnum(e.profit):""].filter(Boolean).join(" · ")),
 h("td",{class:"mu",style:"font-size:11px"},e.by||""),h("td",{class:"mu",style:"white-space:normal;max-width:260px"},e.note||""))))}
async function ledgerModal(a){const r=await call("panel/agency/ledger?"+q({agent:a.id,limit:300}));
 const m=modal(X("ledger")+" — "+a.username,h("div",{},h("div",{style:"margin-bottom:8px"},X("balance")+": ",h("b",{class:"num",style:"color:"+color(r.balance)},money(r.balance))),ledgerTable(r.items)),
  [h("a",{class:"btn",href:BASE+"panel/agency/ledger?"+q({agent:a.id,format:"csv"})},"⬇ "+X("csv")),h("button",{class:"btn",onclick:()=>m.remove()},t("cancel"))]);m.querySelector(".card").style.width="min(900px,100%)"}

/* ---------- wallet / ledger ---------- */
async function pWallet(c){if(ME.agent.perms.subAgents&&!AGENTS.length)await loadAgents();
 const S={agent:"",kind:"",range:"d30",q:""};const body=h("div");
 const load=async()=>{const [from,to]=rangeOf(S.range);const p={agent:S.agent,kind:S.kind,q:S.q,from:from||"",to:to||"",limit:1000};const r=await call("panel/agency/ledger?"+q(p));
  const sum=k=>r.items.filter(e=>k(e)).reduce((s,e)=>s+e.amt,0);
  put(body,h("div",{class:"dg"},stat("💰","#10b981",X("balance"),money(r.balance),X("credit")+": "+money(Math.max(ME.agent.limits.creditLimit||0,ME.agent.limits.maxDebt||0))),
    stat("⬆","#3b82f6",X("topups"),money(sum(e=>e.kind==="topup"||e.kind==="transfer_in"))),stat("🛒","#ef4444",X("paid"),money(-sum(e=>["sale","renew","addgb","adddays","reset","refund","reversal"].includes(e.kind))))),
   ledgerTable(r.items,r.names),h("a",{class:"btn",href:BASE+"panel/agency/ledger?"+q({...p,format:"csv",limit:""})},"⬇ "+X("csv")))};
 const kinds=h("select",{onchange:e=>{S.kind=e.target.value;load()}},[h("option",{value:""},t("all")),...Object.entries(X("kinds")).map(([k,l])=>h("option",{value:k},l))]);
 const search=h("input",{placeholder:X("search"),oninput:e=>{S.q=e.target.value;clearTimeout(search._t);search._t=setTimeout(load,300)}});
 put(c,h("div",{class:"top"},h("h2",{},X("wallet"))),h("div",{class:"row"},AGENTS.length?agentSel(S.agent||ME.agent.id,v=>{S.agent=v;load()}):null,kinds,rangeSel(S.range,v=>{S.range=v;load()}),search),body);
 await load()}

/* ---------- customers ---------- */
async function pCustomers(c){const body=h("div");
 const load=async()=>{const list=await call("panel/agency/customers");
  put(body,tbl([X("name"),X("phone"),X("tgid"),X("acctlist"),X("note"),X("created"),""],list.map(x=>h("tr",{},h("td",{},h("b",{},x.name)),h("td",{class:"num"},x.phone||""),h("td",{class:"num"},x.tgId||""),
   h("td",{},h("a",{style:"cursor:pointer;color:var(--pr)",onclick:()=>{AS.customer=String(x.id);AS.owner="";AS.page=1;go("accounts")}},fnum(x.active)+" / "+fnum(x.accounts))),
   h("td",{class:"mu",style:"white-space:normal;max-width:280px"},x.note||""),h("td",{class:"mu"},fmtDate(x.created)),
   h("td",{class:"ops"},ib("✎",t("edit"),()=>edit(x)),ib("🗑",t("del"),async()=>{if(!confirm(t("confirm")))return;await post("panel/agency/customers/del",{id:x.id});load()},"d"))))))};
 const edit=x=>{x=x||{id:0,name:"",phone:"",tgId:"",note:""};const f={n:h("input",{value:x.name}),p:h("input",{value:x.phone,dir:"ltr"}),tg:h("input",{value:x.tgId,dir:"ltr"}),note:h("textarea",{rows:3,style:"flex:1"},x.note)};
  const m=modal(x.id?t("edit"):"+ "+X("customer"),h("div",{},field(X("name"),f.n),field(X("phone"),f.p),field(X("tgid"),f.tg),field(X("note"),f.note)),[h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
   h("button",{class:"btn p",onclick:async()=>{await post("panel/agency/customers/save",{id:x.id,name:f.n.value,phone:f.p.value,tgId:f.tg.value,note:f.note.value});m.remove();load()}},t("save"))])};
 put(c,h("div",{class:"top"},h("h2",{},X("customers")),h("button",{class:"btn p",onclick:()=>edit()},"+ "+X("customer"))),body);await load()}

/* ---------- reports ---------- */
async function pReports(c){if(!AGENTS.length&&(ME.role==="admin"||ME.agent.perms.subAgents))await loadAgents();
 const S={range:"d30",group:"day",agent:"",inactive:7};const body=h("div");
 const load=async()=>{const [from,to]=rangeOf(S.range);const p={from:from||"",to:to||"",group:S.group,agent:S.agent,inactive:S.inactive};const r=await call("panel/agency/reports?"+q(p));const T0=r.totals;
  const isAdmin=ME.role==="admin"&&!S.agent;const max=Math.max(1,...r.series.map(x=>x.revenue));
  const kv=o=>Object.entries(o||{}).sort((a,b)=>b[1].amount-a[1].amount);
  put(body,
   h("div",{class:"dg"},stat("🆕","#6366f1",X("newsales"),fnum(T0.sales)),stat("🔁","#3b82f6",X("renews"),fnum(T0.renews)),stat("📦","#06b6d4",t("traffic"),fnum(+T0.gb.toFixed(1))+" GB"),
    stat("💵","#10b981",isAdmin?X("revenue"):X("paid"),money(T0.revenue)),!isAdmin?stat("📈","#f59e0b",X("profit"),money(T0.profit)):stat("⬆","#f59e0b",X("topups"),money(T0.topups)),stat("↩","#ef4444",X("refunds"),money(T0.refunds))),
   tbl([X("period"),X("newsales"),X("renews"),"GB",isAdmin?X("revenue"):X("paid"),!isAdmin?X("profit"):X("topups"),""],r.series.map(x=>h("tr",{},h("td",{},x.k),h("td",{},fnum(x.sales)),h("td",{},fnum(x.renews)),h("td",{class:"num"},fnum(+x.gb.toFixed(1))),
    h("td",{class:"num"},fnum(x.revenue)),h("td",{class:"num"},fnum(isAdmin?x.topups:x.profit)),h("td",{style:"width:30%"},h("div",{class:"bar"},h("i",{style:"width:"+Math.round(x.revenue*100/max)+"%"})))))),
   r.agents.length?sec("🏆 "+X("top"),tbl([t("name"),X("newsales"),X("renews"),"GB",X("paid"),X("profit"),X("balance"),X("lastsale")],r.agents.map(a=>h("tr",{},h("td",{},h("b",{},a.username),a.brand?h("span",{class:"mu"}," "+a.brand):null),
    h("td",{},fnum(a.sales)),h("td",{},fnum(a.renews)),h("td",{class:"num"},fnum(+a.gb.toFixed(1))),h("td",{class:"num"},fnum(a.paid)),h("td",{class:"num"},fnum(a.profit)),h("td",{class:"num",style:"color:"+color(a.balance)},fnum(a.balance)),h("td",{class:"mu"},a.lastSale?fmtDate(a.lastSale):"-"))))):null,
   h("div",{style:"display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px"},
    sec(X("protos"),tbl([t("proto"),X("count"),X("amount")],kv(r.protocols).map(([k,v])=>h("tr",{},h("td",{},h("span",{class:"tag"},k)),h("td",{},fnum(v.count)),h("td",{class:"num"},fnum(v.amount)))))),
    sec(X("plans"),tbl([X("plan"),X("count"),X("amount")],kv(r.plans).map(([k,v])=>h("tr",{},h("td",{},v.name),h("td",{},fnum(v.count)),h("td",{class:"num"},fnum(v.amount)))))),
    (r.inactive||[]).length?sec("💤 "+X("inactive"),tbl([t("name"),X("lastsale")],r.inactive.map(a=>h("tr",{},h("td",{},a.username),h("td",{class:"mu"},a.lastSale?fmtDate(a.lastSale):t("never")))))):null,
    (r.debtors||[]).length?sec("📉 "+X("debtors"),tbl([t("name"),X("balance")],r.debtors.map(a=>h("tr",{},h("td",{},a.username),h("td",{class:"num",style:"color:var(--er)"},fnum(a.balance)))))):null),
   h("a",{class:"btn",href:BASE+"panel/agency/reports?"+q({...p,format:"csv"})},"⬇ "+X("csv")))};
 const grp=h("select",{onchange:e=>{S.group=e.target.value;load()}},[["day","byday"],["week","byweek"],["month","bymonth"]].map(([v,k])=>h("option",{value:v},X(k))));
 const ina=h("input",{type:"number",min:1,value:S.inactive,style:"width:70px",title:X("inactivedays"),onchange:e=>{S.inactive=+e.target.value||7;load()}});
 put(c,h("div",{class:"top"},h("h2",{},X("reports"))),h("div",{class:"row"},rangeSel(S.range,v=>{S.range=v;load()}),grp,AGENTS.length?agentSel(S.agent,v=>{S.agent=v;load()},true):null,
  AGENTS.length?h("span",{class:"mu"},X("inactivedays")):null,AGENTS.length?ina:null),body);await load()}

/* ---------- reseller dashboard ---------- */
async function pAgDash(c){
 const draw=async()=>{const d=await call("panel/agency/dashboard");refreshMe();const st=d.accounts.status||{},S=d.stats||{};const s0=k=>S[k]||{};
  const quick=h("div",{class:"card",style:"display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px"},ME.agent.perms.create?h("button",{class:"btn p",onclick:()=>sellModal(draw)},"+ "+X("sell")):null,
   h("button",{class:"btn",onclick:()=>go("accounts")},"👥 "+t("accounts")),h("button",{class:"btn",onclick:()=>go("wallet")},"💰 "+X("wallet")),h("button",{class:"btn",onclick:()=>go("reports")},"📈 "+X("reports")));
  const acctRow=x=>h("tr",{},h("td",{},h("b",{},x.email)),h("td",{class:"num"},fmtB(x.used)+" / "+(x.total?fmtB(x.total):"∞")),h("td",{},leftText(x.expiry)),
   h("td",{},ME.agent.perms.renew?h("button",{class:"btn s p",onclick:()=>renewModal([x.email],draw)},X("renew")):null));
  put(c,h("div",{class:"top"},h("h2",{},t("dash")),h("span",{class:"mu"},ME.agent.title||"")),
   d.frozen?h("div",{class:"card",style:"margin-bottom:12px;border-color:var(--er);color:var(--er)"},"⛔ "+X("frozenmsg")):null,quick,
   h("div",{class:"dg"},stat("💰",d.balance<0?"#ef4444":"#10b981",X("balance"),money(d.balance),X("credit")+": "+money(d.creditLimit)),
    stat("👥","#6366f1",X("ownacc"),fnum(d.accounts.own),d.accounts.subtree?X("subacc")+": "+fnum(d.accounts.subtree):null),stat("🌐","#10b981",t("online"),fnum(d.accounts.online),t("traffic")+": "+fmtB(d.accounts.used||0)),
    stat("✅","#3b82f6",t("active"),fnum(st.active||0)),stat("📅","#ef4444",t("expired")+" / "+t("depleted"),fnum((st.expired||0)+(st.depleted||0))),stat("🚫","#f59e0b",t("disabled"),fnum(st.disabled||0)),
    stat("🛒","#6366f1",X("today"),fnum((s0("today").sales||0)+(s0("today").renews||0)),money(s0("today").paid||0)),stat("🗓","#06b6d4",X("d7"),fnum((s0("week").sales||0)+(s0("week").renews||0)),money(s0("week").paid||0)),
    stat("📆","#8b5cf6",X("d30"),fnum((s0("month").sales||0)+(s0("month").renews||0)),money(s0("month").paid||0)),d.children?stat("📈","#f59e0b",X("profit")+" (30d)",money(s0("month").profit||0)):null),
   d.expiring&&d.expiring.length?sec("⏳ "+X("expiring"),tbl([t("name"),t("used"),t("expiry"),""],d.expiring.map(acctRow))):null,
   d.low&&d.low.length?sec("📦 "+X("lowq"),tbl([t("name"),t("used"),t("expiry"),""],d.low.map(acctRow))):null,
   sec("🧾 "+X("recent"),ledgerTable(d.recent||[])))};
 await draw();auto(draw,30000)}

/* ---------- profile (reseller) ---------- */
async function pProfile(c){await refreshMe();await loadPlans();const a=ME.agent,P=a.perms,L=a.limits,e=ME.prices||{};
 const pw={o:h("input",{type:"password"}),n:h("input",{type:"password"})};
 const kv=(k,v)=>h("div",{class:"row",style:"margin-bottom:4px"},h("label",{},k),h("b",{},v));
 const keysBox=h("div");
 const loadKeys=async()=>{if(!P.api){put(keysBox,);return}const r=await call("panel/agency/keys");const allow=h("input",{value:(r.allow||[]).join(", "),dir:"ltr"}),rate=num0(r.rate);
  const origin=location.origin+BASE;
  put(keysBox,sec("🔑 "+X("keys"),tbl(["ID",t("name"),X("created"),X("lastuse"),""],(r.keys||[]).map(k=>h("tr",{},h("td",{class:"num"},"vl_"+k.id+"…"),h("td",{},k.name||""),h("td",{class:"mu"},fmtDate(k.created)),h("td",{class:"mu"},k.lastUse?ago(k.lastUse):t("never")),
     h("td",{},h("button",{class:"btn s d",onclick:async()=>{if(!confirm(t("confirm")))return;await post("panel/agency/keys/del",{id:k.id});loadKeys()}},t("del")))))),
    h("button",{class:"btn p",onclick:async()=>{const name=prompt(t("name"),"shop")||"";const r2=await post("panel/agency/keys/new",{name});
     const m=modal(X("newkey"),h("div",{},h("div",{class:"mu"},X("keyonce")),h("pre",{},r2.key)),[copyBtn(r2.key),h("button",{class:"btn p",onclick:()=>{m.remove();loadKeys()}},"OK")])}},"+ "+X("newkey")),
    h("div",{style:"margin-top:12px"},field(X("allowip"),allow),field(X("rate"),rate),h("button",{class:"btn",onclick:async()=>{await post("panel/agency/keys/allow",{allow:allow.value.split(/[,\s]+/).filter(Boolean),rate:+rate.value||0});toast(t("saved"))}},t("save"))),
    h("h4",{},X("apidoc")),h("pre",{dir:"ltr",style:"text-align:left"},
     "Header:  X-API-Key: vl_...\n\n"+
     "GET  "+origin+"panel/agency/whoami                  (balance, prices, services)\n"+
     "GET  "+origin+"panel/agency/plans\n"+
     "POST "+origin+"panel/agency/quote   {\"plan\":1} | {\"kind\":\"sale\",\"gb\":10,\"days\":30}\n"+
     "POST "+origin+"panel/agency/sell    {\"username\":\"ali\",\"plan\":1,\"inbounds\":[1,2]}\n"+
     "POST "+origin+"panel/agency/renew   {\"emails\":[\"ali\"],\"plan\":1}\n"+
     "GET  "+origin+"panel/ui/accounts?q=ali\n"+
     "GET  "+origin+"panel/agency/ledger\n\n"+
     "The old panel API (what the bot uses) also works with the key:\n"+
     "GET  "+origin+"panel/api/inbounds/list\n"+
     "POST "+origin+"panel/api/inbounds/addClient | updateClient/{id} | {inbound}/delClientByEmail/{email}")))};
 put(c,h("div",{class:"top"},h("h2",{},X("profile"))),
  sec("👤 "+a.username,kv(X("brand"),a.brand||"-"),kv(X("title"),a.title||"-"),kv(X("level"),fnum(ME.level)),kv(X("expiry"),a.expiry?fmtDate(a.expiry)+" — "+leftText(a.expiry):t("unl")),
   kv(X("balance"),money(ME.balance)),kv(X("credit"),money(Math.max(L.creditLimit||0,L.maxDebt||0))),
   h("h4",{},X("perms")),h("div",{},Object.keys(X("P")).filter(k=>P[k]).map(k=>h("span",{class:"tag",style:"margin:2px"},X("P")[k]))),
   h("h4",{},X("limits")),h("div",{},Object.keys(X("L")).filter(k=>L[k]).map(k=>h("span",{class:"tag",style:"margin:2px"},X("L")[k]+": "+fnum(L[k]))),Object.keys(X("L")).some(k=>L[k])?null:h("span",{class:"mu"},"—"))),
  sec("💲 "+X("myprices"),h("div",{class:"dg"},stat("📦","#6366f1",X("PR").perGB,money(e.perGB||0)),stat("📅","#06b6d4",X("PR").perDay,money(e.perDay||0)),stat("➕","#10b981",X("PR").addGB,money(e.addGB||0)),stat("⏱","#f59e0b",X("PR").addDay,money(e.addDay||0))),
   PLANS.length?tbl([X("plan"),"GB",X("days"),X("plansell"),X("planrenew")],PLANS.map(p=>h("tr",{},h("td",{},p.name),h("td",{},p.gb?fnum(p.gb):"∞"),h("td",{},p.days?fnum(+(+p.days).toFixed(2)):"∞"),h("td",{class:"num"},money(p.myPrice)),h("td",{class:"num"},money(p.myRenew))))):null,
   h("div",{class:"mu",style:"font-size:12px"},X("formula"))),
  sec("🔒 "+X("chpw"),field(X("oldpw"),pw.o),field(X("newpw6"),pw.n),h("button",{class:"btn p",onclick:async()=>{await post("panel/agency/password",{old:pw.o.value,new:pw.n.value});toast(t("saved"));pw.o.value=pw.n.value=""}},t("save"))),
  keysBox);
 await loadKeys()}

/* ---------- admin: plans, rules, ledger, requests, activity ---------- */
async function pAgency(c){let tab=sessionStorage.getItem("agtab")||"plans";const body=h("div");
 const tabs=["plans","rules","ledger","requests","activity","apilog"];
 const bar=()=>h("div",{class:"row"},tabs.map(k=>h("button",{class:"btn"+(k===tab?" p":""),onclick:()=>{tab=k;sessionStorage.setItem("agtab",k);draw()}},X(k)+(k==="requests"&&ME.pendingRequests?" ("+fnum(ME.pendingRequests)+")":""))));
 const draw=async()=>{put(c,h("div",{class:"top"},h("h2",{},X("agency"))),bar(),body);put(body,h("div",{class:"mu"},"…"));await ({plans:tPlans,rules:tRules,ledger:tLedger,requests:tRequests,activity:tActivity,apilog:tAPILog}[tab])(body)};
 await draw()}
async function tPlans(b){await loadPlans();
 const edit=p=>{p=p||{id:0,name:"",gb:30,days:30,price:0,renew:0,devices:0,inbounds:[],enable:true,order:0};
  const f={n:h("input",{value:p.name}),gb:num0(p.gb),d:num0(+(+p.days).toFixed(4)),pr:num0(p.price),rn:num0(p.renew),dev:num0(p.devices),o:num0(p.order),en:h("input",{type:"checkbox",class:"sw",checked:p.enable})};
  const svc=(ME.services||[]).map(s=>[s,h("input",{type:"checkbox",checked:(p.inbounds||[]).includes(s.id)})]);
  const m=modal(p.id?t("edit")+" — "+p.name:"+ "+X("plan"),h("div",{},field(X("planname"),f.n),field(X("gb")+" (0=∞)",f.gb),field(X("days")+" (0=∞, 0.0834=2h)",f.d),field(X("price"),f.pr),field(X("renewprice"),f.rn),
   field(X("devices"),f.dev),field(X("services"),h("div",{style:"flex:1"},svc.map(([s,x])=>h("label",{style:"display:inline-block;width:auto;color:inherit;margin-inline-end:10px"},x," ",s.remark||s.protocol)))),field(X("order"),f.o),field(X("enabled"),f.en)),[
   p.id?h("button",{class:"btn d",onclick:async()=>{if(!confirm(t("confirm")))return;await post("panel/agency/plans/del",{id:p.id});m.remove();tPlans(b)}},t("del")):null,
   h("button",{class:"btn",onclick:()=>m.remove()},t("cancel")),
   h("button",{class:"btn p",onclick:async()=>{await post("panel/agency/plans/save",{id:p.id,name:f.n.value,gb:+f.gb.value||0,days:+f.d.value||0,price:Math.round(+f.pr.value||0),renew:Math.round(+f.rn.value||0),
    devices:+f.dev.value||0,inbounds:svc.filter(([s,x])=>x.checked).map(([s])=>s.id),enable:f.en.checked,order:+f.o.value||0});toast(t("saved"));m.remove();tPlans(b)}},t("save"))])};
 put(b,h("div",{class:"row"},h("button",{class:"btn p",onclick:()=>edit()},"+ "+X("plan"))),
  tbl([X("planname"),"GB",X("days"),X("price"),X("planrenew"),X("devices"),X("status"),""],PLANS.map(p=>h("tr",{},h("td",{},h("b",{},p.name)),h("td",{},p.gb?fnum(p.gb):"∞"),h("td",{},p.days?fnum(+(+p.days).toFixed(3)):"∞"),
   h("td",{class:"num"},money(p.price)),h("td",{class:"num"},money(p.renew||p.price)),h("td",{},p.devices||"-"),h("td",{},h("span",{class:"pill "+(p.enable?"active":"disabled")},p.enable?X("enabled"):t("disabled"))),
   h("td",{},h("button",{class:"btn s",onclick:()=>edit(p)},t("edit")))))),h("div",{class:"mu",style:"font-size:12px"},X("formula")))}
async function tRules(b){const s=await call("panel/agency/settings");const R=s.refund||{};
 const f={cur:h("input",{value:s.currency}),gb:num0(s.perGB),d:num0(s.perDay),agb:num0(s.addGB,{placeholder:fnum(s.perGB)}),ad:num0(s.addDay,{placeholder:fnum(s.perDay)}),lv:num0(s.maxLevels),
  mode:h("select",{},["none","window","prorated"].map(k=>h("option",{value:k,selected:R.mode===k},X("r"+k)))),hrs:num0(R.hours),used:num0(R.maxUsedPct),pct:num0(R.percent),
  low:num0(s.lowBalance),ns:h("input",{type:"checkbox",class:"sw",checked:s.notifySale})};
 put(b,sec(X("baseprices"),field(X("currency"),f.cur),field(X("PR").perGB,f.gb),field(X("PR").perDay,f.d),field(X("PR").addGB,f.agb),field(X("PR").addDay,f.ad),h("div",{class:"mu",style:"font-size:12px"},X("formula"))),
  sec(X("refund"),field(X("status"),f.mode),field(X("rhours"),f.hrs),field(X("rused"),f.used),field(X("rpct"),f.pct)),
  sec(X("agency"),field(X("maxlevels"),f.lv),field(X("lowbal"),f.low),field(X("notifysale"),f.ns)),
  h("button",{class:"btn p",onclick:async()=>{await post("panel/agency/settings",{currency:f.cur.value,perGB:Math.round(+f.gb.value||0),perDay:Math.round(+f.d.value||0),addGB:Math.round(+f.agb.value||0),addDay:Math.round(+f.ad.value||0),
   maxLevels:+f.lv.value||1,refund:{mode:f.mode.value,hours:+f.hrs.value||0,maxUsedPct:+f.used.value||0,percent:+f.pct.value||0},lowBalance:Math.round(+f.low.value||0),notifySale:f.ns.checked});
   const j=await call("panel/agency/whoami");ME=j;toast(t("saved"))}},t("save")))}
async function tLedger(b){if(!AGENTS.length)await loadAgents();const S={agent:"",kind:"",range:"d30",q:""};const out=h("div");
 const load=async()=>{const [from,to]=rangeOf(S.range);const p={agent:S.agent,kind:S.kind,q:S.q,from:from||"",to:to||"",limit:1000};const r=await call("panel/agency/ledger?"+q(p));
  put(out,ledgerTable(r.items,r.names),h("a",{class:"btn",href:BASE+"panel/agency/ledger?"+q({...p,format:"csv",limit:""})},"⬇ "+X("csv")))};
 const kinds=h("select",{onchange:e=>{S.kind=e.target.value;load()}},[h("option",{value:""},t("all")),...Object.entries(X("kinds")).map(([k,l])=>h("option",{value:k},l))]);
 const search=h("input",{placeholder:X("search"),oninput:e=>{S.q=e.target.value;clearTimeout(search._t);search._t=setTimeout(load,300)}});
 put(b,h("div",{class:"row"},agentSel(S.agent,v=>{S.agent=v;load()},true),kinds,rangeSel(S.range,v=>{S.range=v;load()}),search),out);await load()}
async function tRequests(b){const r=await call("panel/agency/requests");const nm=id=>r.names[id]||("#"+id);
 put(b,tbl([X("time"),X("move"),X("accts"),X("note"),X("status"),""],r.items.map(x=>h("tr",{},h("td",{class:"mu"},fmtDate(x.t)),h("td",{},nm(x.from)+" → "+nm(x.to)),
  h("td",{style:"white-space:normal;max-width:260px"},x.emails.join(", ")),h("td",{class:"mu"},x.note||""),h("td",{},h("span",{class:"pill "+(x.status==="approved"?"active":x.status==="pending"?"":"expired")},X(x.status))),
  h("td",{},x.status==="pending"?[h("button",{class:"btn s p",onclick:async()=>{await post("panel/agency/requests/decide",{id:x.id,approve:true});toast(t("saved"));ME.pendingRequests=Math.max(0,(ME.pendingRequests||1)-1);tRequests(b)}},X("approve"))," ",
   h("button",{class:"btn s d",onclick:async()=>{const reply=prompt(X("note"))||"";await post("panel/agency/requests/decide",{id:x.id,approve:false,reply});ME.pendingRequests=Math.max(0,(ME.pendingRequests||1)-1);tRequests(b)}},X("reject"))]:h("span",{class:"mu"},x.reply||""))))))}
async function tActivity(b){let action="",qs="";const out=h("div");
 const load=async()=>{const r=await call("panel/agency/activity?"+q({action,q:qs}));
  put(out,tbl([X("time"),X("by"),X("kind"),"",X("note"),"IP"],r.map(x=>h("tr",{},h("td",{class:"mu"},fmtDate(x.t)),h("td",{},x.actor),h("td",{},h("span",{class:"tag"},x.action)),h("td",{class:"mu"},x.target||""),
   h("td",{style:"white-space:normal;max-width:380px"},x.detail||""),h("td",{class:"num mu"},x.ip||"")))))};
 const sel=h("select",{onchange:e=>{action=e.target.value;load()}},["","login","sale","renew","delete","wallet","agent","plan","settings","impersonate","apikey","request","accounts"].map(k=>h("option",{value:k},k||t("all"))));
 const search=h("input",{placeholder:X("search"),oninput:e=>{qs=e.target.value;clearTimeout(search._t);search._t=setTimeout(load,300)}});
 put(b,h("div",{class:"row"},sel,search),out);await load()}
async function tAPILog(b){const r=await call("panel/agency/apilog");
 put(b,tbl([X("time"),X("agents"),"","","IP",""],r.map(x=>h("tr",{},h("td",{class:"mu"},fmtDate(x.t)),h("td",{},AGN[x.agent]||(x.agent?"#"+x.agent:"-")),h("td",{},h("span",{class:"tag"},x.method)),h("td",{class:"num"},x.path),h("td",{class:"num mu"},x.ip),h("td",{style:"color:var(--er)"},x.err||"")))))}

/* ---------- admin dashboard addition ---------- */
async function agencyCard(){try{const d=await call("panel/agency/dashboard");if(!d.agents)return null;const S=d.stats||{},s0=k=>S[k]||{};
 return h("div",{class:"card",style:"margin-bottom:14px"},h("h3",{style:"margin-top:0;cursor:pointer",onclick:()=>go("agents")},"🤝 "+X("agents")),
  h("div",{class:"dg",style:"margin-bottom:0"},stat("🤝","#6366f1",X("agents"),fnum(d.agents),X("agentaccts")+": "+fnum(d.agentAccounts)),stat("💰","#10b981",X("totalbal"),money(d.balances),X("totaldebt")+": "+money(d.debt)),
   stat("💵","#f59e0b",X("revenue")+" — "+X("today"),money(s0("today").revenue||0),fnum((s0("today").sales||0))+" "+X("newsales")),stat("📆","#8b5cf6",X("revenue")+" — "+X("d30"),money(s0("month").revenue||0),fnum(s0("month").sales||0)+" "+X("newsales")),
   d.pendingRequests?stat("📨","#ef4444",X("requests"),fnum(d.pendingRequests)):null))}catch(e){return null}}

document.head.append(h("style",{},"td.num{display:table-cell}.bar-sel .btn{color:#1e1b4b}"));
window.agencySetup=async function(){
 window.shellTop=()=>ME.impersonated?h("div",{class:"bar-sel"},"👁 "+X("watching")+": ",h("b",{},ME.agent.username),h("span",{style:"flex:1"}),
  h("button",{class:"btn s",onclick:async()=>{await post("panel/agency/back");location.hash="#/agents";location.reload()}},"↩ "+X("back"))):null;
 if(ME.role==="agent"){const P=ME.agent.perms;
  PAGES=["dash","accounts","online","wallet","customers"];if(P.subAgents)PAGES.push("subagents");PAGES.push("reports","profile");
  Object.assign(ICON,{wallet:"💰",customers:"🧑‍💼",subagents:"🌳",reports:"📈",profile:"👤"});
  Object.assign(PAGEFN,{dash:pAgDash,wallet:pWallet,customers:pCustomers,subagents:pAgents,reports:pReports,profile:pProfile});
  window.sideTop=balBox;
  window.accTop=load=>[P.create?h("button",{class:"btn p",onclick:()=>sellModal(load)},"+ "+X("sell")):null,P.create&&P.bulk?h("button",{class:"btn",onclick:()=>agBulkCreate(load)},t("bulkc")):null];
  window.accRowExtra=(a,load)=>P.renew?ib("⟳",X("renew"),()=>renewModal([a.email],load)):null;
  window.bulkExtra=(emails,done)=>[P.renew?h("button",{class:"btn s",onclick:()=>renewModal(emails,done)},"⟳ "+X("renew")):null,
   P.transfer?h("button",{class:"btn s",onclick:()=>moveModal(emails,done)},"↪ "+X("move")):null,h("button",{class:"btn s",onclick:()=>custModal(emails,done)},"🧑‍💼 "+X("customer"))];
  if(P.subAgents)await loadAgents().catch(()=>{});
 }else{
  PAGES=["dash","accounts","inbounds","online","agents","reports","agency","logs","settings"];
  Object.assign(ICON,{agents:"🤝",reports:"📈",agency:"🏪"});
  Object.assign(PAGEFN,{agents:pAgents,reports:pReports,agency:pAgency});
  window.bulkExtra=(emails,done)=>Object.keys(AGN).length?h("button",{class:"btn s",onclick:()=>moveModal(emails,done)},"🏷 "+X("move")):null;
  window.dashExtra=agencyCard;
  await loadAgents().catch(()=>{});
 }
};
})();
