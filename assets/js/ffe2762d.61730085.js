"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[7228],{95788:(e,t,r)=>{r.r(t),r.d(t,{MDXContext:()=>m,MDXProvider:()=>d,mdx:()=>y,useMDXComponents:()=>p,withMDXComponents:()=>l});var a=r(11504);function n(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(){return o=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var a in r)Object.prototype.hasOwnProperty.call(r,a)&&(e[a]=r[a])}return e},o.apply(this,arguments)}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,a)}return r}function s(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){n(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function c(e,t){if(null==e)return{};var r,a,n=function(e,t){if(null==e)return{};var r,a,n={},o=Object.keys(e);for(a=0;a<o.length;a++)r=o[a],t.indexOf(r)>=0||(n[r]=e[r]);return n}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)r=o[a],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(n[r]=e[r])}return n}var m=a.createContext({}),l=function(e){return function(t){var r=p(t.components);return a.createElement(e,o({},t,{components:r}))}},p=function(e){var t=a.useContext(m),r=t;return e&&(r="function"==typeof e?e(t):s(s({},t),e)),r},d=function(e){var t=p(e.components);return a.createElement(m.Provider,{value:t},e.children)},f="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},b=a.forwardRef((function(e,t){var r=e.components,n=e.mdxType,o=e.originalType,i=e.parentName,m=c(e,["components","mdxType","originalType","parentName"]),l=p(r),d=n,f=l["".concat(i,".").concat(d)]||l[d]||u[d]||o;return r?a.createElement(f,s(s({ref:t},m),{},{components:r})):a.createElement(f,s({ref:t},m))}));function y(e,t){var r=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var o=r.length,i=new Array(o);i[0]=b;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s[f]="string"==typeof e?e:n,i[1]=s;for(var m=2;m<o;m++)i[m]=r[m];return a.createElement.apply(null,i)}return a.createElement.apply(null,r)}b.displayName="MDXCreateElement"},73712:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>c,contentTitle:()=>i,default:()=>d,frontMatter:()=>o,metadata:()=>s,toc:()=>m});var a=r(45072),n=(r(11504),r(95788));const o={sidebar_position:70,title:"Data Formats"},i="Project Aria Data Formats",s={unversionedId:"data_formats/data_formats",id:"data_formats/data_formats",title:"Data Formats",description:"In this section, we describe:",source:"@site/docs/data_formats/data_formats.mdx",sourceDirName:"data_formats",slug:"/data_formats/",permalink:"/projectaria_tools/docs/data_formats/",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/data_formats/data_formats.mdx",tags:[],version:"current",sidebarPosition:70,frontMatter:{sidebar_position:70,title:"Data Formats"},sidebar:"tutorialSidebar",previous:{title:"Device Calibration",permalink:"/projectaria_tools/docs/tech_spec/device_calibration"},next:{title:"Aria VRS",permalink:"/projectaria_tools/docs/data_formats/aria_vrs/"}},c={},m=[],l={toc:m},p="wrapper";function d(e){let{components:t,...r}=e;return(0,n.mdx)(p,(0,a.c)({},l,r,{components:t,mdxType:"MDXLayout"}),(0,n.mdx)("h1",{id:"project-aria-data-formats"},"Project Aria Data Formats"),(0,n.mdx)("p",null,"In this section, we describe:"),(0,n.mdx)("ul",null,(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/projectaria_tools/docs/data_formats/aria_vrs/"},"How Project Aria uses VRS to store raw data")),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/data_formats/mps/mps_summary"},"How Machine Perception Services (MPS) data is formatted"),(0,n.mdx)("ul",{parentName:"li"},(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/ARK/mps"},"MPS")," produces derived data that is useful for machine perception algorithms"))),(0,n.mdx)("li",{parentName:"ul"},(0,n.mdx)("a",{parentName:"li",href:"/docs/data_formats/coordinate_convention/2d_image_coordinate_system_convention"},"2D")," and ",(0,n.mdx)("a",{parentName:"li",href:"/docs/data_formats/coordinate_convention/3d_coordinate_frame_convention"},"3D Coordinate System Conventions"))))}d.isMDXComponent=!0}}]);