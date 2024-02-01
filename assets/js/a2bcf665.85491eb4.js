"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[8256],{95788:(e,t,a)=>{a.r(t),a.d(t,{MDXContext:()=>c,MDXProvider:()=>m,mdx:()=>g,useMDXComponents:()=>d,withMDXComponents:()=>p});var r=a(11504);function o(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function s(){return s=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var a=arguments[t];for(var r in a)Object.prototype.hasOwnProperty.call(a,r)&&(e[r]=a[r])}return e},s.apply(this,arguments)}function n(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function i(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?n(Object(a),!0).forEach((function(t){o(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):n(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function l(e,t){if(null==e)return{};var a,r,o=function(e,t){if(null==e)return{};var a,r,o={},s=Object.keys(e);for(r=0;r<s.length;r++)a=s[r],t.indexOf(a)>=0||(o[a]=e[a]);return o}(e,t);if(Object.getOwnPropertySymbols){var s=Object.getOwnPropertySymbols(e);for(r=0;r<s.length;r++)a=s[r],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(o[a]=e[a])}return o}var c=r.createContext({}),p=function(e){return function(t){var a=d(t.components);return r.createElement(e,s({},t,{components:a}))}},d=function(e){var t=r.useContext(c),a=t;return e&&(a="function"==typeof e?e(t):i(i({},t),e)),a},m=function(e){var t=d(e.components);return r.createElement(c.Provider,{value:t},e.children)},u="mdxType",h={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},f=r.forwardRef((function(e,t){var a=e.components,o=e.mdxType,s=e.originalType,n=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),p=d(a),m=o,u=p["".concat(n,".").concat(m)]||p[m]||h[m]||s;return a?r.createElement(u,i(i({ref:t},c),{},{components:a})):r.createElement(u,i({ref:t},c))}));function g(e,t){var a=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var s=a.length,n=new Array(s);n[0]=f;var i={};for(var l in t)hasOwnProperty.call(t,l)&&(i[l]=t[l]);i.originalType=e,i[u]="string"==typeof e?e:o,n[1]=i;for(var c=2;c<s;c++)n[c]=a[c];return r.createElement.apply(null,n)}return r.createElement.apply(null,a)}f.displayName="MDXCreateElement"},48972:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>c,contentTitle:()=>i,default:()=>u,frontMatter:()=>n,metadata:()=>l,toc:()=>p});var r=a(45072),o=(a(11504),a(95788)),s=a(89908);const n={sidebar_position:40,title:"MPS Data Processing"},i="MPS Data Lifecycle",l={unversionedId:"ARK/mps/mps_processing",id:"ARK/mps/mps_processing",title:"MPS Data Processing",description:"Overview",source:"@site/docs/ARK/mps/mps_processing.mdx",sourceDirName:"ARK/mps",slug:"/ARK/mps/mps_processing",permalink:"/projectaria_tools/docs/ARK/mps/mps_processing",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/ARK/mps/mps_processing.mdx",tags:[],version:"current",sidebarPosition:40,frontMatter:{sidebar_position:40,title:"MPS Data Processing"},sidebar:"tutorialSidebar",previous:{title:"Eye Gaze Calibration",permalink:"/projectaria_tools/docs/ARK/mps/eye_gaze_calibration"},next:{title:"ARK Release Notes",permalink:"/projectaria_tools/docs/ARK/sw_release_notes"}},c={},p=[{value:"Overview",id:"overview",level:2},{value:"How sequences are processed",id:"how-sequences-are-processed",level:2},{value:"Data storage and use",id:"data-storage-and-use",level:2}],d={toc:p},m="wrapper";function u(e){let{components:t,...a}=e;return(0,o.mdx)(m,(0,r.c)({},d,a,{components:t,mdxType:"MDXLayout"}),(0,o.mdx)("h1",{id:"mps-data-lifecycle"},"MPS Data Lifecycle"),(0,o.mdx)("h2",{id:"overview"},"Overview"),(0,o.mdx)("p",null,"Researchers can upload data collected by Project Aria glasses to Meta for cloud-based Machine Perception Services (MPS) processing."),(0,o.mdx)("p",null,"This page provides information about how all Aria sequences submitted to Meta for MPS are processed, handled and stored."),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},"Go to ",(0,o.mdx)("a",{parentName:"li",href:"/docs/ARK/mps"},"Machine Perception Services"),"\xa0to find out more about the data"),(0,o.mdx)("li",{parentName:"ul"},"Go to ",(0,o.mdx)("a",{parentName:"li",href:"/docs/ARK/mps/request_mps"},"How to Request MPS"),"\xa0for how to get your data processed")),(0,o.mdx)("h2",{id:"how-sequences-are-processed"},"How sequences are processed"),(0,o.mdx)("ol",null,(0,o.mdx)("li",{parentName:"ol"},"Raw Aria sequences (VRS files) are uploaded to secure cloud storage via the Desktop Companion app"),(0,o.mdx)("li",{parentName:"ol"},"The data is only uploaded to Meta servers to serve MPS requests and is immediately deleted from the server after processing"),(0,o.mdx)("li",{parentName:"ol"},"The MPS output is saved in the cloud",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},"User account that requested the MPS gets the token necessary to access MPS outputs"),(0,o.mdx)("li",{parentName:"ul"},"This derived data is persisted in the cloud"))),(0,o.mdx)("li",{parentName:"ol"},"Raw data is deleted from the cloud",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},"Meta\u2019s data management processes mandate that this raw data cannot be stored for more than 24 hours"),(0,o.mdx)("li",{parentName:"ul"},"MPS processing is much faster than this and the data is deleted as soon as processing is complete")))),(0,o.mdx)("div",{style:{textAlign:"center"}},(0,o.mdx)("img",{width:"100%",src:(0,s.default)("/img/ARK/mps_processing.png"),alt:"Diagram of MPS Processing lifecycle, as described above"}),(0,o.mdx)("p",null,(0,o.mdx)("strong",{parentName:"p"},"Figure 1:")," ",(0,o.mdx)("em",{parentName:"p"},"MPS Processing Lifecycle"))),(0,o.mdx)("h2",{id:"data-storage-and-use"},"Data storage and use"),(0,o.mdx)("ul",null,(0,o.mdx)("li",{parentName:"ul"},"Partner data is only used to serve MPS requests. Partner data is not\xa0available to Meta researchers or Meta\u2019s affiliates."),(0,o.mdx)("li",{parentName:"ul"},"Raw partner data (VRS files) are ephemeral and are deleted as soon as the MPS processing is complete."),(0,o.mdx)("li",{parentName:"ul"},"The whole process is automated and only engineers in the core MPS team can access the pipeline."),(0,o.mdx)("li",{parentName:"ul"},"All ",(0,o.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_summary"},"MPS output")," (trajectories, semi-dense point clouds, gaze vectors etc.)\xa0continues to be stored in secure cloud storage, so that users can re-download the data at any time. MPS output is not\xa0available to Meta researchers or Meta\u2019s affiliates.",(0,o.mdx)("ul",{parentName:"li"},(0,o.mdx)("li",{parentName:"ul"},"Only the user account that requested the MPS output gets the token necessary to download the derived data"),(0,o.mdx)("li",{parentName:"ul"},"Our goal is for this data to always be available to the user who requested it, however, if the Desktop App\u2019s local cache is cleared you may no longer have the token necessary to access the data."))),(0,o.mdx)("li",{parentName:"ul"},"The MPS pipeline generates\xa0statistics about how the algorithms are performing\xa0as well as the console logs from processing. These aggregated statistics are used by the Project Aria MPS team to help improve our offerings.")))}u.isMDXComponent=!0}}]);