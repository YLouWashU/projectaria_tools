"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[8811],{3905:(e,t,a)=>{a.r(t),a.d(t,{MDXContext:()=>d,MDXProvider:()=>p,mdx:()=>x,useMDXComponents:()=>m,withMDXComponents:()=>u});var r=a(67294);function n(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function i(){return i=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var a=arguments[t];for(var r in a)Object.prototype.hasOwnProperty.call(a,r)&&(e[r]=a[r])}return e},i.apply(this,arguments)}function o(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function l(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?o(Object(a),!0).forEach((function(t){n(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):o(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function s(e,t){if(null==e)return{};var a,r,n=function(e,t){if(null==e)return{};var a,r,n={},i=Object.keys(e);for(r=0;r<i.length;r++)a=i[r],t.indexOf(a)>=0||(n[a]=e[a]);return n}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)a=i[r],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(n[a]=e[a])}return n}var d=r.createContext({}),u=function(e){return function(t){var a=m(t.components);return r.createElement(e,i({},t,{components:a}))}},m=function(e){var t=r.useContext(d),a=t;return e&&(a="function"==typeof e?e(t):l(l({},t),e)),a},p=function(e){var t=m(e.components);return r.createElement(d.Provider,{value:t},e.children)},c="mdxType",h={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},f=r.forwardRef((function(e,t){var a=e.components,n=e.mdxType,i=e.originalType,o=e.parentName,d=s(e,["components","mdxType","originalType","parentName"]),u=m(a),p=n,c=u["".concat(o,".").concat(p)]||u[p]||h[p]||i;return a?r.createElement(c,l(l({ref:t},d),{},{components:a})):r.createElement(c,l({ref:t},d))}));function x(e,t){var a=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var i=a.length,o=new Array(i);o[0]=f;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[c]="string"==typeof e?e:n,o[1]=l;for(var d=2;d<i;d++)o[d]=a[d];return r.createElement.apply(null,o)}return r.createElement.apply(null,a)}f.displayName="MDXCreateElement"},18679:(e,t,a)=>{a.r(t),a.d(t,{default:()=>o});var r=a(67294),n=a(86010);const i={tabItem:"tabItem_Ymn6"};function o(e){let{children:t,hidden:a,className:o}=e;return r.createElement("div",{role:"tabpanel",className:(0,n.default)(i.tabItem,o),hidden:a},t)}},73992:(e,t,a)=>{a.r(t),a.d(t,{default:()=>N});var r=a(87462),n=a(67294),i=a(86010),o=a(72957),l=a(16550),s=a(75238),d=a(33609),u=a(92560);function m(e){return function(e){return n.Children.map(e,(e=>{if(!e||(0,n.isValidElement)(e)&&function(e){const{props:t}=e;return!!t&&"object"==typeof t&&"value"in t}(e))return e;throw new Error(`Docusaurus error: Bad <Tabs> child <${"string"==typeof e.type?e.type:e.type.name}>: all children of the <Tabs> component should be <TabItem>, and every <TabItem> should have a unique "value" prop.`)}))?.filter(Boolean)??[]}(e).map((e=>{let{props:{value:t,label:a,attributes:r,default:n}}=e;return{value:t,label:a,attributes:r,default:n}}))}function p(e){const{values:t,children:a}=e;return(0,n.useMemo)((()=>{const e=t??m(a);return function(e){const t=(0,d.l)(e,((e,t)=>e.value===t.value));if(t.length>0)throw new Error(`Docusaurus error: Duplicate values "${t.map((e=>e.value)).join(", ")}" found in <Tabs>. Every value needs to be unique.`)}(e),e}),[t,a])}function c(e){let{value:t,tabValues:a}=e;return a.some((e=>e.value===t))}function h(e){let{queryString:t=!1,groupId:a}=e;const r=(0,l.k6)(),i=function(e){let{queryString:t=!1,groupId:a}=e;if("string"==typeof t)return t;if(!1===t)return null;if(!0===t&&!a)throw new Error('Docusaurus error: The <Tabs> component groupId prop is required if queryString=true, because this value is used as the search param name. You can also provide an explicit value such as queryString="my-search-param".');return a??null}({queryString:t,groupId:a});return[(0,s._X)(i),(0,n.useCallback)((e=>{if(!i)return;const t=new URLSearchParams(r.location.search);t.set(i,e),r.replace({...r.location,search:t.toString()})}),[i,r])]}function f(e){const{defaultValue:t,queryString:a=!1,groupId:r}=e,i=p(e),[o,l]=(0,n.useState)((()=>function(e){let{defaultValue:t,tabValues:a}=e;if(0===a.length)throw new Error("Docusaurus error: the <Tabs> component requires at least one <TabItem> children component");if(t){if(!c({value:t,tabValues:a}))throw new Error(`Docusaurus error: The <Tabs> has a defaultValue "${t}" but none of its children has the corresponding value. Available values are: ${a.map((e=>e.value)).join(", ")}. If you intend to show no default tab, use defaultValue={null} instead.`);return t}const r=a.find((e=>e.default))??a[0];if(!r)throw new Error("Unexpected error: 0 tabValues");return r.value}({defaultValue:t,tabValues:i}))),[s,d]=h({queryString:a,groupId:r}),[m,f]=function(e){let{groupId:t}=e;const a=function(e){return e?`docusaurus.tab.${e}`:null}(t),[r,i]=(0,u.Nk)(a);return[r,(0,n.useCallback)((e=>{a&&i.set(e)}),[a,i])]}({groupId:r}),x=(()=>{const e=s??m;return c({value:e,tabValues:i})?e:null})();(0,n.useLayoutEffect)((()=>{x&&l(x)}),[x]);return{selectedValue:o,selectValue:(0,n.useCallback)((e=>{if(!c({value:e,tabValues:i}))throw new Error(`Can't select invalid tab value=${e}`);l(e),d(e),f(e)}),[d,f,i]),tabValues:i}}var x=a(51048);const v={tabList:"tabList__CuJ",tabItem:"tabItem_LNqP"};function g(e){let{className:t,block:a,selectedValue:l,selectValue:s,tabValues:d}=e;const u=[],{blockElementScrollPositionUntilNextRender:m}=(0,o.o5)(),p=e=>{const t=e.currentTarget,a=u.indexOf(t),r=d[a].value;r!==l&&(m(t),s(r))},c=e=>{let t=null;switch(e.key){case"Enter":p(e);break;case"ArrowRight":{const a=u.indexOf(e.currentTarget)+1;t=u[a]??u[0];break}case"ArrowLeft":{const a=u.indexOf(e.currentTarget)-1;t=u[a]??u[u.length-1];break}}t?.focus()};return n.createElement("ul",{role:"tablist","aria-orientation":"horizontal",className:(0,i.default)("tabs",{"tabs--block":a},t)},d.map((e=>{let{value:t,label:a,attributes:o}=e;return n.createElement("li",(0,r.Z)({role:"tab",tabIndex:l===t?0:-1,"aria-selected":l===t,key:t,ref:e=>u.push(e),onKeyDown:c,onClick:p},o,{className:(0,i.default)("tabs__item",v.tabItem,o?.className,{"tabs__item--active":l===t})}),a??t)})))}function b(e){let{lazy:t,children:a,selectedValue:r}=e;const i=(Array.isArray(a)?a:[a]).filter(Boolean);if(t){const e=i.find((e=>e.props.value===r));return e?(0,n.cloneElement)(e,{className:"margin-top--md"}):null}return n.createElement("div",{className:"margin-top--md"},i.map(((e,t)=>(0,n.cloneElement)(e,{key:t,hidden:e.props.value!==r}))))}function y(e){const t=f(e);return n.createElement("div",{className:(0,i.default)("tabs-container",v.tabList)},n.createElement(g,(0,r.Z)({},e,t)),n.createElement(b,(0,r.Z)({},e,t)))}function N(e){const t=(0,x.default)();return n.createElement(y,(0,r.Z)({key:String(t)},e))}},90450:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>d,contentTitle:()=>l,default:()=>c,frontMatter:()=>o,metadata:()=>s,toc:()=>u});var r=a(87462),n=(a(67294),a(3905)),i=a(79524);a(73992),a(18679);const o={sidebar_position:5,title:"Setup Guide"},l="Project Aria Client SDK and CLI Setup Guide",s={unversionedId:"ARK/sdk/setup",id:"ARK/sdk/setup",title:"Setup Guide",description:"Overview",source:"@site/docs/ARK/sdk/setup.mdx",sourceDirName:"ARK/sdk",slug:"/ARK/sdk/setup",permalink:"/projectaria_tools/docs/ARK/sdk/setup",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/ARK/sdk/setup.mdx",tags:[],version:"current",sidebarPosition:5,frontMatter:{sidebar_position:5,title:"Setup Guide"},sidebar:"tutorialSidebar",previous:{title:"About the SDK",permalink:"/projectaria_tools/docs/ARK/sdk/"},next:{title:"Code Samples",permalink:"/projectaria_tools/docs/ARK/sdk/samples/"}},d={},u=[{value:"Overview",id:"overview",level:2},{value:"Requirements",id:"requirements",level:2},{value:"Hardware",id:"hardware",level:3},{value:"Platforms",id:"platforms",level:3},{value:"Software",id:"software",level:3},{value:"Environment Setup",id:"environment-setup",level:2},{value:"Step 1: Install SDK from PyPi",id:"step-1-install-sdk-from-pypi",level:2},{value:"Create a virtual environment",id:"create-a-virtual-environment",level:3},{value:"Install the Client SDK and CLI",id:"install-the-client-sdk-and-cli",level:3},{value:"Step 2: Run Project Aria Doctor utility",id:"step-2-run-project-aria-doctor-utility",level:2},{value:"Step 3: Pair Aria Glasses with your computer",id:"step-3-pair-aria-glasses-with-your-computer",level:2},{value:"Step 4: Extract and explore the sample apps",id:"step-4-extract-and-explore-the-sample-apps",level:2},{value:"Useful Links",id:"useful-links",level:2}],m={toc:u},p="wrapper";function c(e){let{components:t,...a}=e;return(0,n.mdx)(p,(0,r.Z)({},m,a,{components:t,mdxType:"MDXLayout"}),(0,n.mdx)("h1",{id:"project-aria-client-sdk-and-cli-setup-guide"},"Project Aria Client SDK and CLI Setup Guide"),(0,n.mdx)("h2",{id:"overview"},"Overview"),(0,n.mdx)("p",null,"The page provides instructions about how to get started with the Project Aria Client SDK, covering:"),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"#requirements"},"Hardware and software requirements")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"#install"},"Downloading and installing the SDK"),(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"Installing ",(0,n.mdx)("inlineCode",{parentName:"li"},"projectaria_client_sdk")," via pip will also add the ",(0,n.mdx)("a",{parentName:"li",href:"/projectaria_tools/docs/ARK/sdk/cli/"},"Aria CLI")," to your PATH"))),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"#doctor"},"Running Project Aria Doctor to setup your computer and fix common issues")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"#pair"},"Pairing your Aria Glasses")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"#explore"},"Extracting and exploring the sample apps"))),(0,n.mdx)("div",{id:"requirements"}),(0,n.mdx)("h2",{id:"requirements"},"Requirements"),(0,n.mdx)("h3",{id:"hardware"},"Hardware"),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},"Project Aria glasses that have:",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"Completed full device setup using the ",(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/about_ARK#mobile-companion-app-requirements"},"Aria Mobile Companion App")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sw_release_notes"},"Latest up-to-date OS")))),(0,n.mdx)("li",{parentName:"ul"},"If you want to stream over Wi-Fi, you'll need a router, such as Asus, Netgear or TP-Link, that has:",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"No firewall"),(0,n.mdx)("li",{parentName:"ul"},"Supports Wi-Fi 6",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"So that the glasses can connect to the 5GHz band when streaming over Wi-Fi")))))),(0,n.mdx)("admonition",{type:"danger"},(0,n.mdx)("p",{parentName:"admonition"},"The Client SDK does not currently support streaming over corporate, university or public networks. Those networks are protected by many layers of security and firewalls. We recommend using one of the recommended routers listed above to stream over Wi-Fi.")),(0,n.mdx)("h3",{id:"platforms"},"Platforms"),(0,n.mdx)("p",null,"The codebase is supported on the following platforms:"),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},"x64 Linux distributions of:",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"Fedora 36 or newer"),(0,n.mdx)("li",{parentName:"ul"},"Ubuntu jammy (22.04) or newer"))),(0,n.mdx)("li",{parentName:"ul"},"Mac Intel or Mac ARM-based (M1) with MacOS 11 (Big Sur) or newer")),(0,n.mdx)("h3",{id:"software"},"Software"),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},"Python 3 with versions >= 3.8.10 and <= 3.11",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"Python 3.9+ if you want to use the ",(0,n.mdx)("inlineCode",{parentName:"li"},"device_stream")," code sample due to the ",(0,n.mdx)("inlineCode",{parentName:"li"},"fastplotlib")," dependency"),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"https://www.python.org/downloads/"},"Python 3 download page")),(0,n.mdx)("li",{parentName:"ul"},"To check which version of Python 3 you have, use ",(0,n.mdx)("inlineCode",{parentName:"li"},"python3 --version")))),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"https://developer.android.com/studio/command-line/adb"},"ADB")," (optional)",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"In addition to the CLI, you can use ADB to interact with Aria glasses"),(0,n.mdx)("li",{parentName:"ul"},"ADB is one of the ways that you can ",(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/ARK_quickstart#download-data"},"download Aria data"))))),(0,n.mdx)("div",{id:"install"}),(0,n.mdx)("h2",{id:"environment-setup"},"Environment Setup"),(0,n.mdx)("h2",{id:"step-1-install-sdk-from-pypi"},"Step 1: Install SDK from PyPi"),(0,n.mdx)("h3",{id:"create-a-virtual-environment"},"Create a virtual environment"),(0,n.mdx)("p",null,"When using ",(0,n.mdx)("inlineCode",{parentName:"p"},"pip"),", it is best practice to use a virtual environment. This will keep all the modules under one folder and will not break your local environment. Use the following command with your version of Python3."),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre",className:"language-bash"},"python3 -m venv ~/venv\n")),(0,n.mdx)("h3",{id:"install-the-client-sdk-and-cli"},"Install the Client SDK and CLI"),(0,n.mdx)("p",null,"Install ",(0,n.mdx)("inlineCode",{parentName:"p"},"projectaria_client_sdk")," with pip"),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre",className:"language-bash"},"source ~/venv/bin/activate\n\npython -m pip install projectaria_client_sdk --no-cache-dir\n")),(0,n.mdx)("h2",{id:"step-2-run-project-aria-doctor-utility"},"Step 2: Run Project Aria Doctor utility"),(0,n.mdx)("p",null,"The Project Aria Doctor utility can help detect and resolve common issues connecting and streaming from the glasses."),(0,n.mdx)("p",null,"Run the utility and follow the prompts to resolve any issues."),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre",className:"language-bash"},"aria-doctor\n")),(0,n.mdx)("admonition",{type:"info"},(0,n.mdx)("p",{parentName:"admonition"},"If you're on MacOS and lose internet connection while streaming, run ",(0,n.mdx)("inlineCode",{parentName:"p"},"aria-doctor")," again.")),(0,n.mdx)("div",{id:"pair"}),(0,n.mdx)("h2",{id:"step-3-pair-aria-glasses-with-your-computer"},"Step 3: Pair Aria Glasses with your computer"),(0,n.mdx)("p",null,"Pairing your Aria glasses to your computer allows the Client SDK and CLI to control the glasses. A pair of Aria glasses can be paired to multiple computers."),(0,n.mdx)("ol",null,(0,n.mdx)("li",{parentName:"ol"},"Turn on your Aria glasses and connect it to your computer using the provided USB cable"),(0,n.mdx)("li",{parentName:"ol"},"Open the Mobile Companion app on your phone"),(0,n.mdx)("li",{parentName:"ol"},"On your computer, run:")),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre"},"aria auth pair\n")),(0,n.mdx)("ol",{start:5},(0,n.mdx)("li",{parentName:"ol"},"A prompt should then appear in the Mobile app, tap ",(0,n.mdx)("strong",{parentName:"li"},"Approve")," to pair your glasses",(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},"The hash in the terminal and the app should be the same"),(0,n.mdx)("li",{parentName:"ul"},"View (or revoke) certificates by going to ",(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/mobile_companion_app#aria-device-settings"},"Device Settings")),(0,n.mdx)("li",{parentName:"ul"},"The Client SDK Certificate will remain valid until you manually revoke it or factory reset your glasses")))),(0,n.mdx)("div",{style:{textAlign:"center"}},(0,n.mdx)("img",{width:"30%",height:"30%",src:(0,i.default)("img/ARK/sdk/clientsdk.png"),alt:"Companion App Client SDK pairing"})),(0,n.mdx)("admonition",{type:"info"},(0,n.mdx)("p",{parentName:"admonition"},"At this point, you can now use the ",(0,n.mdx)("a",{parentName:"p",href:"/projectaria_tools/docs/ARK/sdk/cli/"},"Aria CLI")," to interact with you Aria glasses.")),(0,n.mdx)("div",{id:"explore"}),(0,n.mdx)("h2",{id:"step-4-extract-and-explore-the-sample-apps"},"Step 4: Extract and explore the sample apps"),(0,n.mdx)("ol",null,(0,n.mdx)("li",{parentName:"ol"},"Extract the Client SDK\xa0code samples (here to your home directory)")),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre",className:"language-bash"},"python -m aria.extract_sdk_samples --output ~\n")),(0,n.mdx)("ol",{start:2},(0,n.mdx)("li",{parentName:"ol"},"Navigate to the sample folder")),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre",className:"language-bash"},"cd ~/projectaria_client_sdk_samples\n")),(0,n.mdx)("ol",{start:3},(0,n.mdx)("li",{parentName:"ol"},"Install necessary dependencies:")),(0,n.mdx)("pre",null,(0,n.mdx)("code",{parentName:"pre",className:"language-bash"},"pip install -r requirements.txt\n")),(0,n.mdx)("p",null,"Go to ",(0,n.mdx)("a",{parentName:"p",href:"/projectaria_tools/docs/ARK/sdk/samples/"},"Code Samples")," to explore Aria Client SDK features."),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/samples/device_connection"},"Connection"),": connect an Aria device to a computer, fetch the device information and status."),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/samples/device_recording"},"Recording"),": start and stop a recording via USB and Wi-Fi."),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/samples/streaming_subscribe"},"Streaming Subscription"),": subscribe to and unsubscribe from a streaming device"),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/samples/device_stream"},"Streaming and Visualizing All Live Sensor Data"),": programmatically start and stop a streaming session, add callbacks to visualize and manipulate the streamed data"),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/samples/undistort_rgb_image"},"Streaming Undistorted RGB Image Using Calibration"),": programmatically start and stop a streaming session, access sensor calibration and undistort an RGB live stream")),(0,n.mdx)("p",null,"Go to ",(0,n.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk/concepts/streaming_internals"},"Streaming Internals")," to understand how streaming works and how to configure your own streaming setup."),(0,n.mdx)("p",null,"If you encounter any issues please run ",(0,n.mdx)("inlineCode",{parentName:"p"},"aria-doctor")," in a separate terminal or check out ",(0,n.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk/sdk_troubleshooting"},"troubleshooting"),"."),(0,n.mdx)("admonition",{type:"info"},(0,n.mdx)("p",{parentName:"admonition"},"You can check your Aria glasses' recording or streaming status in the ",(0,n.mdx)("a",{parentName:"p",href:"/docs/ARK/mobile_companion_app"},"Mobile Companion app"),".")),(0,n.mdx)("admonition",{type:"danger"},(0,n.mdx)("p",{parentName:"admonition"},"The Client SDK does not currently support streaming over corporate, university or public networks. Those networks are protected by many layers of security and firewalls. We recommend using one of the recommended routers listed above to stream over Wi-Fi.")),(0,n.mdx)("h2",{id:"useful-links"},"Useful Links"),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/concepts/streaming_internals"},"Streaming Internals")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/api_reference"},"SDK API Reference")," - full list of APIs"),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/cli/api_reference"},"CLI Command Reference")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/sdk/sdk_troubleshooting"},"SDK & CLI Troubleshooting"))))}c.isMDXComponent=!0}}]);