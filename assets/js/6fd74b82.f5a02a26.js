"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6393],{3905:(e,t,a)=>{a.r(t),a.d(t,{MDXContext:()=>p,MDXProvider:()=>x,mdx:()=>c,useMDXComponents:()=>s,withMDXComponents:()=>o});var r=a(67294);function n(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function l(){return l=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var a=arguments[t];for(var r in a)Object.prototype.hasOwnProperty.call(a,r)&&(e[r]=a[r])}return e},l.apply(this,arguments)}function d(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function m(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?d(Object(a),!0).forEach((function(t){n(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):d(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function i(e,t){if(null==e)return{};var a,r,n=function(e,t){if(null==e)return{};var a,r,n={},l=Object.keys(e);for(r=0;r<l.length;r++)a=l[r],t.indexOf(a)>=0||(n[a]=e[a]);return n}(e,t);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(r=0;r<l.length;r++)a=l[r],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(n[a]=e[a])}return n}var p=r.createContext({}),o=function(e){return function(t){var a=s(t.components);return r.createElement(e,l({},t,{components:a}))}},s=function(e){var t=r.useContext(p),a=t;return e&&(a="function"==typeof e?e(t):m(m({},t),e)),a},x=function(e){var t=s(e.components);return r.createElement(p.Provider,{value:t},e.children)},g="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},N=r.forwardRef((function(e,t){var a=e.components,n=e.mdxType,l=e.originalType,d=e.parentName,p=i(e,["components","mdxType","originalType","parentName"]),o=s(a),x=n,g=o["".concat(d,".").concat(x)]||o[x]||u[x]||l;return a?r.createElement(g,m(m({ref:t},p),{},{components:a})):r.createElement(g,m({ref:t},p))}));function c(e,t){var a=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var l=a.length,d=new Array(l);d[0]=N;var m={};for(var i in t)hasOwnProperty.call(t,i)&&(m[i]=t[i]);m.originalType=e,m[g]="string"==typeof e?e:n,d[1]=m;for(var p=2;p<l;p++)d[p]=a[p];return r.createElement.apply(null,d)}return r.createElement.apply(null,a)}N.displayName="MDXCreateElement"},17963:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>i,contentTitle:()=>d,default:()=>x,frontMatter:()=>l,metadata:()=>m,toc:()=>p});var r=a(87462),n=(a(67294),a(3905));a(79524);const l={sidebar_position:40,title:"API Reference"},d="Aria Client SDK API Reference",m={unversionedId:"ARK/sdk/api_reference",id:"ARK/sdk/api_reference",title:"API Reference",description:"Overview",source:"@site/docs/ARK/sdk/api_reference.mdx",sourceDirName:"ARK/sdk",slug:"/ARK/sdk/api_reference",permalink:"/projectaria_tools/docs/ARK/sdk/api_reference",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/ARK/sdk/api_reference.mdx",tags:[],version:"current",sidebarPosition:40,frontMatter:{sidebar_position:40,title:"API Reference"},sidebar:"tutorialSidebar",previous:{title:"Streaming Internals",permalink:"/projectaria_tools/docs/ARK/sdk/concepts/streaming_internals"},next:{title:"Aria CLI",permalink:"/projectaria_tools/docs/ARK/sdk/cli/"}},i={},p=[{value:"Overview",id:"overview",level:2},{value:"Global Functions &amp; Methods",id:"global-functions--methods",level:2},{value:"Classes",id:"classes",level:2},{value:"aria.sdk.Error",id:"ariasdkerror",level:3},{value:"aria.sdk.RecordingConfig",id:"ariasdkrecordingconfig",level:3},{value:"aria.sdk.StreamingSecurityOptions",id:"ariasdkstreamingsecurityoptions",level:3},{value:"aria.sdk.StreamingConfig",id:"ariasdkstreamingconfig",level:3},{value:"aria.sdk.StreamingSubscriptionConfig",id:"ariasdkstreamingsubscriptionconfig",level:3},{value:"aria.sdk.DeviceInfo",id:"ariasdkdeviceinfo",level:3},{value:"aria.sdk.DeviceStatus",id:"ariasdkdevicestatus",level:3},{value:"aria.sdk.DeviceClientConfig",id:"ariasdkdeviceclientconfig",level:3},{value:"aria.sdk.DeviceClient",id:"ariasdkdeviceclient",level:3},{value:"aria.sdk.Device",id:"ariasdkdevice",level:3},{value:"aria.sdk.RecordingManager",id:"ariasdkrecordingmanager",level:3},{value:"aria.sdk.StreamingManager",id:"ariasdkstreamingmanager",level:3},{value:"aria.sdk.BaseStreamingClientObserver",id:"ariasdkbasestreamingclientobserver",level:3},{value:"aria.sdk.StreamingClient",id:"ariasdkstreamingclient",level:3},{value:"Enums",id:"enums",level:2},{value:"aria.sdk.Level",id:"ariasdklevel",level:3},{value:"aria.sdk.CameraId",id:"ariasdkcameraid",level:3},{value:"aria.sdk.RecordingState",id:"ariasdkrecordingstate",level:3},{value:"aria.sdk.StreamingState",id:"ariasdkstreamingstate",level:3},{value:"aria.sdk.StreamingInterface",id:"ariasdkstreaminginterface",level:3},{value:"aria.sdk.StreamingDataType",id:"ariasdkstreamingdatatype",level:3},{value:"aria.sdk.DeviceMode",id:"ariasdkdevicemode",level:3}],o={toc:p},s="wrapper";function x(e){let{components:t,...a}=e;return(0,n.mdx)(s,(0,r.Z)({},o,a,{components:t,mdxType:"MDXLayout"}),(0,n.mdx)("h1",{id:"aria-client-sdk-api-reference"},"Aria Client SDK API Reference"),(0,n.mdx)("h2",{id:"overview"},"Overview"),(0,n.mdx)("p",null,"This page provides a list of Project Aria Client SDK's APIs."),(0,n.mdx)("h2",{id:"global-functions--methods"},"Global Functions & Methods"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Function"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"set_log_level(level: Level)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Sets the SDK logging verbosity")))),(0,n.mdx)("h2",{id:"classes"},"Classes"),(0,n.mdx)("h3",{id:"ariasdkerror"},"aria.sdk.Error"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"code"),(0,n.mdx)("td",{parentName:"tr",align:null},"int"),(0,n.mdx)("td",{parentName:"tr",align:null},"Error code")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"message"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Human readable error message")))),(0,n.mdx)("h3",{id:"ariasdkrecordingconfig"},"aria.sdk.RecordingConfig"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"profile_name"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Sensors profile name for recording")))),(0,n.mdx)("h3",{id:"ariasdkstreamingsecurityoptions"},"aria.sdk.StreamingSecurityOptions"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"use_ephemeral_certs"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Use ephemeral certs instead of persistent ones")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"local_certs_root_path"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Local directory path where streaming certificates are stored")))),(0,n.mdx)("h3",{id:"ariasdkstreamingconfig"},"aria.sdk.StreamingConfig"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"security_options"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingSecurityOptions"),(0,n.mdx)("td",{parentName:"tr",align:null},"Security options used to start streaming")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"topic_prefix"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Use this as a unique string to prefix all streamed data messages")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"profile_name"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Sensors profile name used to start streaming")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"streaming_interface"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingInterface"),(0,n.mdx)("td",{parentName:"tr",align:null},"Network interface used to start streaming")))),(0,n.mdx)("h3",{id:"ariasdkstreamingsubscriptionconfig"},"aria.sdk.StreamingSubscriptionConfig"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"security_options"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingSecurityOptions"),(0,n.mdx)("td",{parentName:"tr",align:null},"Security options used to subscribe to an existing live secure stream")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"subscriber_data_type"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingDataType"),(0,n.mdx)("td",{parentName:"tr",align:null},"Data types to subscribe to")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"message_queue_size"),(0,n.mdx)("td",{parentName:"tr",align:null},"int"),(0,n.mdx)("td",{parentName:"tr",align:null},"Size for the message queue. A shorter queue size may be useful if the processing callback is always slow and you wish to process more recent data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"subscriber_name"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve the subscriber name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"subscriber_topic_prefix"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve the topic used to prefix the existing live stream")))),(0,n.mdx)("h3",{id:"ariasdkdeviceinfo"},"aria.sdk.DeviceInfo"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"board"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Device board name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"bootloader"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Bootloader version")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"brand"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Device brand name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"manufacturer"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Manufactuer name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"model"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Model name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"product"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Product name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"serial"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Serial number")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"time"),(0,n.mdx)("td",{parentName:"tr",align:null},"int"),(0,n.mdx)("td",{parentName:"tr",align:null},"OS build timestamp")))),(0,n.mdx)("h3",{id:"ariasdkdevicestatus"},"aria.sdk.DeviceStatus"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"battery_level"),(0,n.mdx)("td",{parentName:"tr",align:null},"int"),(0,n.mdx)("td",{parentName:"tr",align:null},"Battery level")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"charger_connected"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"USB charger cable state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"charging"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Charging state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"wifi_enabled"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"WiFi activation state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"wifi_configured"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"WiFi configuration state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"wifi_connected"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"WiFi connection state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"wifi_ip_address"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"WiFi IP address")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"wifi_device_name"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"WiFi device name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"wifi_ssid"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"WiFi SSID name")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"logged_in"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Companion App user login state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"developer_mode"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Developer mode state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"adb_enabled"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"ADB state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"thermal_mitigation_triggered"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Indicate max level temperature has been reached triggering throttling")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"skin_temp_celsius"),(0,n.mdx)("td",{parentName:"tr",align:null},"float"),(0,n.mdx)("td",{parentName:"tr",align:null},"Device temperature")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"default_recording_profile"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Default recording profile used when pressing the top right HW button")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"is_recording_allowed"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Recording capability state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"device_mode"),(0,n.mdx)("td",{parentName:"tr",align:null},"DeviceMode"),(0,n.mdx)("td",{parentName:"tr",align:null},"Device mode")))),(0,n.mdx)("h3",{id:"ariasdkdeviceclientconfig"},"aria.sdk.DeviceClientConfig"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"ip_v4_address"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"IP v4 address to use for connecting to the device via Wi-Fi")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"device_serial"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Device serial number used when connecting to the device via USB (only necessary if multiple devices are plugged in)")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"adb_path"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Specify your own custom ADB version")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"reconnection_attempts"),(0,n.mdx)("td",{parentName:"tr",align:null},"int"),(0,n.mdx)("td",{parentName:"tr",align:null},"Number of reconnection attempts before time out. Defaults to 2")))),(0,n.mdx)("h3",{id:"ariasdkdeviceclient"},"aria.sdk.DeviceClient"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Method"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"create(config: DeviceClientConfig)"),(0,n.mdx)("td",{parentName:"tr",align:null},"DeviceClient"),(0,n.mdx)("td",{parentName:"tr",align:null},"Create DeviceClient instance")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"authenticate()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Authenticate your client using the specified config")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"connect()"),(0,n.mdx)("td",{parentName:"tr",align:null},"Device"),(0,n.mdx)("td",{parentName:"tr",align:null},"Connect to device via Wifi or via USB using the specified config. Setting both ip address and adb path will lead to the adb path being ignored")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"disconnect(device: Device)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Disconnect ",(0,n.mdx)("inlineCode",{parentName:"td"},"Device")," instance")))),(0,n.mdx)("h3",{id:"ariasdkdevice"},"aria.sdk.Device"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Method"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"recording_manager()"),(0,n.mdx)("td",{parentName:"tr",align:null},"RecordingManager"),(0,n.mdx)("td",{parentName:"tr",align:null},"Access recording capabilities")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"streaming_manager()"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingManager"),(0,n.mdx)("td",{parentName:"tr",align:null},"Access streaming capabilities")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"info()"),(0,n.mdx)("td",{parentName:"tr",align:null},"DeviceInfo"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve device information such as device name and serial number")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"status()"),(0,n.mdx)("td",{parentName:"tr",align:null},"DeviceStatus"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve device status such as battery level and device temperature")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"factory_calibration_json()"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve device factory calibration as JSON string")))),(0,n.mdx)("h3",{id:"ariasdkrecordingmanager"},"aria.sdk.RecordingManager"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Method"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"start_recording()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Start recording")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"stop_recording()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Stop recording")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"sensors_calibration()"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve the device calibration computed from the sensors profile used to record")))),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"recording_config"),(0,n.mdx)("td",{parentName:"tr",align:null},"RecordingConfig"),(0,n.mdx)("td",{parentName:"tr",align:null},"Used to configure recording parameters such as the sensors profile")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"recording_state"),(0,n.mdx)("td",{parentName:"tr",align:null},"RecordingState"),(0,n.mdx)("td",{parentName:"tr",align:null},"Determine current recording state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"recording_profiles"),(0,n.mdx)("td",{parentName:"tr",align:null},"List","[str]"),(0,n.mdx)("td",{parentName:"tr",align:null},"Returns a list of existing profile names to use to start recording")))),(0,n.mdx)("h3",{id:"ariasdkstreamingmanager"},"aria.sdk.StreamingManager"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Method"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"start_streaming()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Start streaming")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"stop_streaming()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Stop streaming")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"sensors_calibration()"),(0,n.mdx)("td",{parentName:"tr",align:null},"str"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve the device calibration computed from the sensors profile used to stream")))),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Property"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"streaming_config"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingConfig"),(0,n.mdx)("td",{parentName:"tr",align:null},"Used to configure streaming parameters related to network interface, security, and sensors profile")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"streaming_state"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingState"),(0,n.mdx)("td",{parentName:"tr",align:null},"Determine current streaming state")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"streaming_profiles"),(0,n.mdx)("td",{parentName:"tr",align:null},"List","[str]"),(0,n.mdx)("td",{parentName:"tr",align:null},"Returns a list of existing profile names to use to start streaming")))),(0,n.mdx)("h3",{id:"ariasdkbasestreamingclientobserver"},"aria.sdk.BaseStreamingClientObserver"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Method"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"on_streaming_client_failure(reason: ErrorCode, message: str)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve streaming failure")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"on_image_received(image_and_record: projectaria_tools.core.sensor_data.ImageDataAndRecord)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve image data streamed from rgb, slam1, slam2 or eye tracking camera sensors")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"on_audio_received(audio_and_record: projectaria_tools.core.sensor_data.AudioDataAndRecord)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve audio data streamed from microphone sensors")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"on_imu_received(motion_data: List","[projectaria_tools.core.sensor_data.MotionData]",", imu_idx: int)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve imu data streamed from IMU1 and IMU2 sensors. Use ",(0,n.mdx)("inlineCode",{parentName:"td"},"imu_idx")," to determine the IMU")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"on_magneto_received(magneto_data: projectaria_tools.core.sensor_data.MotionData)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve magnetometer data streamed from magnetometer sensor")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"on_baro_received(baro_data: projectaria_tools.core.sensor_data.BarometerData)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Retrieve barometer data streamed from barometer sensor")))),(0,n.mdx)("h3",{id:"ariasdkstreamingclient"},"aria.sdk.StreamingClient"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Method"),(0,n.mdx)("th",{parentName:"tr",align:null},"Type"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"create()"),(0,n.mdx)("td",{parentName:"tr",align:null},"StreamingClient"),(0,n.mdx)("td",{parentName:"tr",align:null},"Create StreamingClient instance")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"subscribe()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Subscribe to data streamed from Aria")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"unsubscribe()"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Unsubscribe to data streamed from Aria")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"set_streaming_client_observer(observer: StreamingClientObserver)"),(0,n.mdx)("td",{parentName:"tr",align:null},"None"),(0,n.mdx)("td",{parentName:"tr",align:null},"Sets the observer to subscribe to the data streamed from Aria")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"is_subscribed()"),(0,n.mdx)("td",{parentName:"tr",align:null},"bool"),(0,n.mdx)("td",{parentName:"tr",align:null},"Returns streaming subscription state")))),(0,n.mdx)("h2",{id:"enums"},"Enums"),(0,n.mdx)("h3",{id:"ariasdklevel"},"aria.sdk.Level"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Disabled"),(0,n.mdx)("td",{parentName:"tr",align:null},"Disable all logs")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Error"),(0,n.mdx)("td",{parentName:"tr",align:null},"Print only error logs")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Warning"),(0,n.mdx)("td",{parentName:"tr",align:null},"Print warning and error logs")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Info"),(0,n.mdx)("td",{parentName:"tr",align:null},"Print info, warning and error logs (default)")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Debug"),(0,n.mdx)("td",{parentName:"tr",align:null},"Print debug, info, warning and error logs")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Trace"),(0,n.mdx)("td",{parentName:"tr",align:null},"Print all logs")))),(0,n.mdx)("h3",{id:"ariasdkcameraid"},"aria.sdk.CameraId"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Slam1"),(0,n.mdx)("td",{parentName:"tr",align:null},"Slam camera 1 sensor")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Slam2"),(0,n.mdx)("td",{parentName:"tr",align:null},"Slam camera 2 sensor")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Rgb"),(0,n.mdx)("td",{parentName:"tr",align:null},"Rgb camera sensor")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"EyeTrack"),(0,n.mdx)("td",{parentName:"tr",align:null},"Eye tracking camera sensors")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Invalid"),(0,n.mdx)("td",{parentName:"tr",align:null},"Unknown camera sensor")))),(0,n.mdx)("h3",{id:"ariasdkrecordingstate"},"aria.sdk.RecordingState"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"NotStarted"),(0,n.mdx)("td",{parentName:"tr",align:null},"Recording not started")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Started"),(0,n.mdx)("td",{parentName:"tr",align:null},"Recording stopped")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Streaming"),(0,n.mdx)("td",{parentName:"tr",align:null},"Recording in progress")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Stopped"),(0,n.mdx)("td",{parentName:"tr",align:null},"Recording stopped")))),(0,n.mdx)("h3",{id:"ariasdkstreamingstate"},"aria.sdk.StreamingState"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"NotStarted"),(0,n.mdx)("td",{parentName:"tr",align:null},"Streaming not started")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Started"),(0,n.mdx)("td",{parentName:"tr",align:null},"Streaming stopped")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Streaming"),(0,n.mdx)("td",{parentName:"tr",align:null},"Streaming in progress")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Stopped"),(0,n.mdx)("td",{parentName:"tr",align:null},"Streaming stopped")))),(0,n.mdx)("h3",{id:"ariasdkstreaminginterface"},"aria.sdk.StreamingInterface"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"WifiStation"),(0,n.mdx)("td",{parentName:"tr",align:null},"Stream through WiFi router")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Usb"),(0,n.mdx)("td",{parentName:"tr",align:null},"Stream through USB cable")))),(0,n.mdx)("h3",{id:"ariasdkstreamingdatatype"},"aria.sdk.StreamingDataType"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Unknown"),(0,n.mdx)("td",{parentName:"tr",align:null})),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Rgb"),(0,n.mdx)("td",{parentName:"tr",align:null},"Rgb sensor data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Slam"),(0,n.mdx)("td",{parentName:"tr",align:null},"Slam1 and Slam2 sensors data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"EyeTrack"),(0,n.mdx)("td",{parentName:"tr",align:null},"Eye tracking sensors data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Audio"),(0,n.mdx)("td",{parentName:"tr",align:null},"Microphones data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Imu"),(0,n.mdx)("td",{parentName:"tr",align:null},"Imu sensors data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Magneto"),(0,n.mdx)("td",{parentName:"tr",align:null},"Magnetometer sensor data")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Baro"),(0,n.mdx)("td",{parentName:"tr",align:null},"Barometer sensor data")))),(0,n.mdx)("h3",{id:"ariasdkdevicemode"},"aria.sdk.DeviceMode"),(0,n.mdx)("table",null,(0,n.mdx)("thead",{parentName:"table"},(0,n.mdx)("tr",{parentName:"thead"},(0,n.mdx)("th",{parentName:"tr",align:null},"Name"),(0,n.mdx)("th",{parentName:"tr",align:null},"Description"))),(0,n.mdx)("tbody",{parentName:"table"},(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Research"),(0,n.mdx)("td",{parentName:"tr",align:null},"Research mode")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Partner"),(0,n.mdx)("td",{parentName:"tr",align:null},"Partner mode")),(0,n.mdx)("tr",{parentName:"tbody"},(0,n.mdx)("td",{parentName:"tr",align:null},"Prototype"),(0,n.mdx)("td",{parentName:"tr",align:null},"Prototype mode")))))}x.isMDXComponent=!0}}]);