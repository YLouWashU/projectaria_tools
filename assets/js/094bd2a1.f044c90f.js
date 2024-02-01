"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[2916],{95788:(e,r,n)=>{n.r(r),n.d(r,{MDXContext:()=>u,MDXProvider:()=>p,mdx:()=>b,useMDXComponents:()=>c,withMDXComponents:()=>l});var t=n(11504);function o(e,r,n){return r in e?Object.defineProperty(e,r,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[r]=n,e}function i(){return i=Object.assign||function(e){for(var r=1;r<arguments.length;r++){var n=arguments[r];for(var t in n)Object.prototype.hasOwnProperty.call(n,t)&&(e[t]=n[t])}return e},i.apply(this,arguments)}function d(e,r){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);r&&(t=t.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),n.push.apply(n,t)}return n}function a(e){for(var r=1;r<arguments.length;r++){var n=null!=arguments[r]?arguments[r]:{};r%2?d(Object(n),!0).forEach((function(r){o(e,r,n[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):d(Object(n)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(n,r))}))}return e}function s(e,r){if(null==e)return{};var n,t,o=function(e,r){if(null==e)return{};var n,t,o={},i=Object.keys(e);for(t=0;t<i.length;t++)n=i[t],r.indexOf(n)>=0||(o[n]=e[n]);return o}(e,r);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(t=0;t<i.length;t++)n=i[t],r.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(o[n]=e[n])}return o}var u=t.createContext({}),l=function(e){return function(r){var n=c(r.components);return t.createElement(e,i({},r,{components:n}))}},c=function(e){var r=t.useContext(u),n=r;return e&&(n="function"==typeof e?e(r):a(a({},r),e)),n},p=function(e){var r=c(e.components);return t.createElement(u.Provider,{value:r},e.children)},m="mdxType",v={inlineCode:"code",wrapper:function(e){var r=e.children;return t.createElement(t.Fragment,{},r)}},f=t.forwardRef((function(e,r){var n=e.components,o=e.mdxType,i=e.originalType,d=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),l=c(n),p=o,m=l["".concat(d,".").concat(p)]||l[p]||v[p]||i;return n?t.createElement(m,a(a({ref:r},u),{},{components:n})):t.createElement(m,a({ref:r},u))}));function b(e,r){var n=arguments,o=r&&r.mdxType;if("string"==typeof e||o){var i=n.length,d=new Array(i);d[0]=f;var a={};for(var s in r)hasOwnProperty.call(r,s)&&(a[s]=r[s]);a.originalType=e,a[m]="string"==typeof e?e:o,d[1]=a;for(var u=2;u<i;u++)d[u]=n[u];return t.createElement.apply(null,d)}return t.createElement.apply(null,n)}f.displayName="MDXCreateElement"},75564:(e,r,n)=>{n.r(r),n.d(r,{assets:()=>s,contentTitle:()=>d,default:()=>p,frontMatter:()=>i,metadata:()=>a,toc:()=>u});var t=n(45072),o=(n(11504),n(95788));const i={sidebar_position:80,title:"Fix USB Driver Issues in Linux"},d=void 0,a={unversionedId:"ARK/troubleshooting/linux_usb_driver",id:"ARK/troubleshooting/linux_usb_driver",title:"Fix USB Driver Issues in Linux",description:"Overview",source:"@site/docs/ARK/troubleshooting/linux_usb_driver.mdx",sourceDirName:"ARK/troubleshooting",slug:"/ARK/troubleshooting/linux_usb_driver",permalink:"/projectaria_tools/docs/ARK/troubleshooting/linux_usb_driver",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/ARK/troubleshooting/linux_usb_driver.mdx",tags:[],version:"current",sidebarPosition:80,frontMatter:{sidebar_position:80,title:"Fix USB Driver Issues in Linux"},sidebar:"tutorialSidebar",previous:{title:"Reduce VRS File Size",permalink:"/projectaria_tools/docs/ARK/troubleshooting/reduce_vrs_file_size"},next:{title:"Get Support",permalink:"/projectaria_tools/docs/ARK/troubleshooting/get_support"}},s={},u=[{value:"Overview",id:"overview",level:2},{value:"Prerequisites",id:"prerequisites",level:2},{value:"Instructions",id:"instructions",level:2},{value:"Look for Aria device",id:"look-for-aria-device",level:3},{value:"Change udev",id:"change-udev",level:3},{value:"Step 1: Get VENDOR_ID and PRODUCT_ID",id:"step-1-get-vendor_id-and-product_id",level:4},{value:"Step 2: Modify 51-android.rules",id:"step-2-modify-51-androidrules",level:4}],l={toc:u},c="wrapper";function p(e){let{components:r,...n}=e;return(0,o.mdx)(c,(0,t.c)({},l,n,{components:r,mdxType:"MDXLayout"}),(0,o.mdx)("h2",{id:"overview"},"Overview"),(0,o.mdx)("p",null,"If the Aria Desktop app or computer can't detect a Project Aria device, it may be that your Aria device's battery is drained, or in Linux it may be because of your USB driver."),(0,o.mdx)("p",null,"Use the following instructions to resolve USB driver issues in Linux."),(0,o.mdx)("h2",{id:"prerequisites"},"Prerequisites"),(0,o.mdx)("p",null,(0,o.mdx)("a",{parentName:"p",href:"https://developer.android.com/tools/adb"},"Android Device Bridge (ADB)")),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},"To install ADB use ",(0,o.mdx)("inlineCode",{parentName:"li"},"sudo apt-get android-tools"))),(0,o.mdx)("h2",{id:"instructions"},"Instructions"),(0,o.mdx)("h3",{id:"look-for-aria-device"},"Look for Aria device"),(0,o.mdx)("p",null,"With your Aria device plugged into your computer, use the command ",(0,o.mdx)("inlineCode",{parentName:"p"},"adb devices"),"."),(0,o.mdx)("p",null,"If your device can be found, you'll get an output like:"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-cpp"},"List of devices attached\n1820dc10 device\n")),(0,o.mdx)("p",null,"If you see no permissions:"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-cpp"},"List of devices attached\n1820dc10    no permissions\n")),(0,o.mdx)("p",null,"you likely need to change your udev."),(0,o.mdx)("h3",{id:"change-udev"},"Change udev"),(0,o.mdx)("p",null,"The following instructions were taken from ",(0,o.mdx)("a",{parentName:"p",href:"https://wiki.archlinux.org/index.php/Android_Debug_Bridge"},"Arch Linux's Android Debug Bridge instructions")," and ",(0,o.mdx)("a",{parentName:"p",href:"http://www.janosgyerik.com/adding-udev-rules-for-usb-debugging-android-devices/"},"Janos Gyerik's Adding udev rules"),":"),(0,o.mdx)("h4",{id:"step-1-get-vendor_id-and-product_id"},"Step 1: Get VENDOR_ID and PRODUCT_ID"),(0,o.mdx)("p",null,"Use list devices to find the ","[VENDOR_ID]"," and ","[PRODUCT_ID]"," of your Aria device."),(0,o.mdx)("p",null,"The command"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-cpp"},"lsusb\n")),(0,o.mdx)("p",null,"should show something like:"),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-cpp"},"Bus 002 Device 002: ID 2833:0086 Facebook, Inc. Aria\n")),(0,o.mdx)("p",null,"In the example above, ","[VENDOR_ID]"," = 2833 and ","[PRODUCT_ID]","=0086"),(0,o.mdx)("h4",{id:"step-2-modify-51-androidrules"},"Step 2: Modify 51-android.rules"),(0,o.mdx)("p",null,"Using ",(0,o.mdx)("inlineCode",{parentName:"p"},"lsusb")," will create a new file ",(0,o.mdx)("inlineCode",{parentName:"p"},"/etc/udev/rules.d/51-android.rules")),(0,o.mdx)("p",null,"Modify 51-android.rules using the following commands or script.  Make sure you create a group called ",(0,o.mdx)("inlineCode",{parentName:"p"},"adbusers")," and ",(0,o.mdx)("inlineCode",{parentName:"p"},"$USER"),", so that you have the correct permissions."),(0,o.mdx)("p",null,(0,o.mdx)("strong",{parentName:"p"},"Commands")),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-cpp"},'$ cat /etc/udev/rules.d/51-android.rules\nSUBSYSTEM=="usb", ATTR{idVendor}=="2833", MODE="0660", GROUP="adbusers", TAG+="uaccess"\nSUBSYSTEM=="usb", ATTR{idVendor}=="2833", ATTR{idProduct}=="0086", MODE="0660", GROUP="adbusers", SYMLINK+="android_adb"\nSUBSYSTEM=="usb", ATTR{idVendor}=="2833", ATTR{idProduct}=="0086", MODE="0660", GROUP="adbusers", SYMLINK+="android_fastboot"\n')),(0,o.mdx)("p",null,"Reboot your workstation to ensure the changes are applied."),(0,o.mdx)("p",null,(0,o.mdx)("strong",{parentName:"p"},"Script")),(0,o.mdx)("p",null,"This script will will apply the previous commands and reboot your workstation."),(0,o.mdx)("pre",null,(0,o.mdx)("code",{parentName:"pre",className:"language-cpp"},'IDs=$(lsusb | grep Facebook)\nif [[ "$?" -ne 0 ]]; then\n  echo "Make sure you have your VROS device connected to your workstation"\n  exit\nfi\nIDs=$(echo $IDs | cut -d " " -f 6)\nVID=$(echo $IDs | cut -d ":" -f 1)\nPID=$(echo $IDs | cut -d ":" -f 2)\nconf_f=/etc/udev/rules.d/51-android.rules\nsudo touch ${conf_f}\necho "SUBSYSTEM==\\"usb\\", ATTR{idVendor}==\\"$VID\\", MODE=\\"0660\\", GROUP=\\"adbusers\\", TAG+=\\"uaccess\\""  >> $conf_f\necho "SUBSYSTEM==\\"usb\\", ATTR{idVendor}==\\"$VID\\", ATTR{idProduct}==\\"$PID\\", MODE=\\"0660\\", GROUP=\\"adbusers\\", SYMLINK+=\\"android_adb\\"" >> $conf_f\necho "SUBSYSTEM=="usb", ATTR{idVendor}==\\"$VID\\", ATTR{idProduct}==\\"$PID\\", MODE=\\"0660\\", GROUP=\\"adbusers\\", SYMLINK+=\\"android_fastboot\\""   >> $conf_f\nsudo groupadd adbusers\nsudo usermod -aG adbusers $USER\n')))}p.isMDXComponent=!0}}]);