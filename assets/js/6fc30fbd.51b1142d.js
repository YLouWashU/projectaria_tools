"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6037],{3905:(e,a,r)=>{r.r(a),r.d(a,{MDXContext:()=>l,MDXProvider:()=>c,mdx:()=>h,useMDXComponents:()=>u,withMDXComponents:()=>d});var t=r(67294);function i(e,a,r){return a in e?Object.defineProperty(e,a,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[a]=r,e}function n(){return n=Object.assign||function(e){for(var a=1;a<arguments.length;a++){var r=arguments[a];for(var t in r)Object.prototype.hasOwnProperty.call(r,t)&&(e[t]=r[t])}return e},n.apply(this,arguments)}function s(e,a){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var t=Object.getOwnPropertySymbols(e);a&&(t=t.filter((function(a){return Object.getOwnPropertyDescriptor(e,a).enumerable}))),r.push.apply(r,t)}return r}function o(e){for(var a=1;a<arguments.length;a++){var r=null!=arguments[a]?arguments[a]:{};a%2?s(Object(r),!0).forEach((function(a){i(e,a,r[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):s(Object(r)).forEach((function(a){Object.defineProperty(e,a,Object.getOwnPropertyDescriptor(r,a))}))}return e}function m(e,a){if(null==e)return{};var r,t,i=function(e,a){if(null==e)return{};var r,t,i={},n=Object.keys(e);for(t=0;t<n.length;t++)r=n[t],a.indexOf(r)>=0||(i[r]=e[r]);return i}(e,a);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);for(t=0;t<n.length;t++)r=n[t],a.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var l=t.createContext({}),d=function(e){return function(a){var r=u(a.components);return t.createElement(e,n({},a,{components:r}))}},u=function(e){var a=t.useContext(l),r=a;return e&&(r="function"==typeof e?e(a):o(o({},a),e)),r},c=function(e){var a=u(e.components);return t.createElement(l.Provider,{value:a},e.children)},p="mdxType",g={inlineCode:"code",wrapper:function(e){var a=e.children;return t.createElement(t.Fragment,{},a)}},b=t.forwardRef((function(e,a){var r=e.components,i=e.mdxType,n=e.originalType,s=e.parentName,l=m(e,["components","mdxType","originalType","parentName"]),d=u(r),c=i,p=d["".concat(s,".").concat(c)]||d[c]||g[c]||n;return r?t.createElement(p,o(o({ref:a},l),{},{components:r})):t.createElement(p,o({ref:a},l))}));function h(e,a){var r=arguments,i=a&&a.mdxType;if("string"==typeof e||i){var n=r.length,s=new Array(n);s[0]=b;var o={};for(var m in a)hasOwnProperty.call(a,m)&&(o[m]=a[m]);o.originalType=e,o[p]="string"==typeof e?e:i,s[1]=o;for(var l=2;l<n;l++)s[l]=r[l];return t.createElement.apply(null,s)}return t.createElement.apply(null,r)}b.displayName="MDXCreateElement"},14281:(e,a,r)=>{r.r(a),r.d(a,{assets:()=>l,contentTitle:()=>o,default:()=>p,frontMatter:()=>s,metadata:()=>m,toc:()=>d});var t=r(87462),i=(r(67294),r(3905)),n=r(79524);const s={sidebar_position:40,title:"Streaming Subscription"},o="Subscribe to Aria Streaming Data",m={unversionedId:"ARK/sdk/samples/streaming_subscribe",id:"ARK/sdk/samples/streaming_subscribe",title:"Streaming Subscription",description:"Overview",source:"@site/docs/ARK/sdk/samples/streaming_subscribe.mdx",sourceDirName:"ARK/sdk/samples",slug:"/ARK/sdk/samples/streaming_subscribe",permalink:"/projectaria_tools/docs/ARK/sdk/samples/streaming_subscribe",draft:!1,editUrl:"https://github.com/facebookresearch/projectaria_tools/tree/main/website/docs/ARK/sdk/samples/streaming_subscribe.mdx",tags:[],version:"current",sidebarPosition:40,frontMatter:{sidebar_position:40,title:"Streaming Subscription"},sidebar:"tutorialSidebar",previous:{title:"Recording",permalink:"/projectaria_tools/docs/ARK/sdk/samples/device_recording"},next:{title:"Streaming and Visualizing All Live Sensor Data",permalink:"/projectaria_tools/docs/ARK/sdk/samples/device_stream"}},l={},d=[{value:"Overview",id:"overview",level:2},{value:"Stream and subscribe examples",id:"stream-and-subscribe-examples",level:2},{value:"Example 1: Stream and subscribe over USB",id:"example-1-stream-and-subscribe-over-usb",level:3},{value:"Example 2: Using Wi-Fi",id:"example-2-using-wi-fi",level:3},{value:"Code walkthrough",id:"code-walkthrough",level:3},{value:"1. Configure the subscription",id:"1-configure-the-subscription",level:4},{value:"2. Set message queue size",id:"2-set-message-queue-size",level:4},{value:"3. Set streaming security options",id:"3-set-streaming-security-options",level:4},{value:"4. Create an StreamingClient observer and attach it",id:"4-create-an-streamingclient-observer-and-attach-it",level:4},{value:"5. Start subscribing and listen to the live stream",id:"5-start-subscribing-and-listen-to-the-live-stream",level:4},{value:"6. Visualize the live stream",id:"6-visualize-the-live-stream",level:4},{value:"7. Unsubscribe from the stream and free resources",id:"7-unsubscribe-from-the-stream-and-free-resources",level:3}],u={toc:d},c="wrapper";function p(e){let{components:a,...r}=e;return(0,i.mdx)(c,(0,t.Z)({},u,r,{components:a,mdxType:"MDXLayout"}),(0,i.mdx)("h1",{id:"subscribe-to-aria-streaming-data"},"Subscribe to Aria Streaming Data"),(0,i.mdx)("h2",{id:"overview"},"Overview"),(0,i.mdx)("p",null,"This ",(0,i.mdx)("inlineCode",{parentName:"p"},"streaming_subscribe")," example shows how to subscribe to and unsubscribe from a streaming session as well as visualize the live stream, using the ",(0,i.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk"},"Project Aria Client SDK"),"."),(0,i.mdx)("h2",{id:"stream-and-subscribe-examples"},"Stream and subscribe examples"),(0,i.mdx)("h3",{id:"example-1-stream-and-subscribe-over-usb"},"Example 1: Stream and subscribe over USB"),(0,i.mdx)("p",null,"In this example, the CLI is used to initiate streaming and the Client SDK is used to subscribe to the stream. To find out how to start streaming using the SDK, go to ",(0,i.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk/samples/device_stream"},"Streaming Sensor Data"),"."),(0,i.mdx)("ol",null,(0,i.mdx)("li",{parentName:"ol"},"Plug your Aria glasses into your computer, using the provided cable"),(0,i.mdx)("li",{parentName:"ol"},"From the samples directory in Terminal, run:")),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-bash"},"aria streaming start --interface usb --use-ephemeral-certs\n")),(0,i.mdx)("ol",{start:3},(0,i.mdx)("li",{parentName:"ol"},"Wait for the stream to start then run:")),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-bash"},"python -m streaming_subscribe\n")),(0,i.mdx)("p",null,"You should then see:"),(0,i.mdx)("div",{style:{textAlign:"center"}},(0,i.mdx)("img",{src:(0,n.default)("img/ARK/sdk/streaming_subscribe.png"),alt:"Aria Live Stream Window"})),(0,i.mdx)("ol",{start:4},(0,i.mdx)("li",{parentName:"ol"},"There are several ways you can stop streaming:")),(0,i.mdx)("ul",null,(0,i.mdx)("li",{parentName:"ul"},"Press q or ESC to quit the app"),(0,i.mdx)("li",{parentName:"ul"},"Use Ctrl-C to terminate in terminal"),(0,i.mdx)("li",{parentName:"ul"},"Press the Capture button on your glasses")),(0,i.mdx)("h3",{id:"example-2-using-wi-fi"},"Example 2: Using Wi-Fi"),(0,i.mdx)("p",null,"To use Wi-Fi to initiate streaming or to stream data, alter the ",(0,i.mdx)("inlineCode",{parentName:"p"},"aria streaming start --interface usb --use-ephemeral-certs")," command."),(0,i.mdx)("ul",null,(0,i.mdx)("li",{parentName:"ul"},"To stream data over Wi-Fi, use ",(0,i.mdx)("inlineCode",{parentName:"li"},"--interface wifi")),(0,i.mdx)("li",{parentName:"ul"},"To initiate streaming over Wi-Fi, add ",(0,i.mdx)("inlineCode",{parentName:"li"},"--device-ip <glasses IP>"),(0,i.mdx)("ul",{parentName:"li"},(0,i.mdx)("li",{parentName:"ul"},"Open the Mobile Companion app and tap ",(0,i.mdx)("a",{parentName:"li",href:"/docs/ARK/mobile_companion_app#dashboard"},"Wi-Fi on the Dashboard")," to see your glasses' IP address")))),(0,i.mdx)("h3",{id:"code-walkthrough"},"Code walkthrough"),(0,i.mdx)("h4",{id:"1-configure-the-subscription"},"1. Configure the subscription"),(0,i.mdx)("p",null,"Use ",(0,i.mdx)("inlineCode",{parentName:"p"},"subscriber_data_type")," attribute to set the type of data the client subscribes to."),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"config = streaming_client.subscription_config\nconfig.subscriber_data_type = (\n    aria.StreamingDataType.Rgb | aria.StreamingDataType.Slam\n)\n")),(0,i.mdx)("h4",{id:"2-set-message-queue-size"},"2. Set message queue size"),(0,i.mdx)("p",null,"The message queue size determines how many recent frames will be retained. A smaller queue size is utilized to process only the most recent data."),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"config.message_queue_size[aria.StreamingDataType.Rgb] = 1\nconfig.message_queue_size[aria.StreamingDataType.Slam] = 1\n")),(0,i.mdx)("h4",{id:"3-set-streaming-security-options"},"3. Set streaming security options"),(0,i.mdx)("p",null,"Security options are set to use ephemeral certificates through a ",(0,i.mdx)("inlineCode",{parentName:"p"},"StreamingSecurityOptions")," instance. Go to ",(0,i.mdx)("a",{parentName:"p",href:"/docs/ARK/sdk/concepts/streaming_internals"},"the Streaming Internals page")," for various aspects of streaming security and how certificates are used."),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"options = aria.StreamingSecurityOptions()\noptions.use_ephemeral_certs = True\nconfig.security_options = options\n")),(0,i.mdx)("h4",{id:"4-create-an-streamingclient-observer-and-attach-it"},"4. Create an StreamingClient observer and attach it"),(0,i.mdx)("p",null,"Find more description of observer in the ",(0,i.mdx)("a",{parentName:"p",href:"http://localhost:3000/projectaria_tools/docs/ARK/sdk/samples/device_stream#3-write-callbacks-for-each-sensor-data-stream"},"streaming code sample")),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"class StreamingClientObserver:\n    def __init__(self):\n        self.images = {}\n\n    def on_image_received(self, image: np.array, record: ImageDataRecord):\n        self.images[record.camera_id] = image\n\nobserver = StreamingClientObserver()\nstreaming_client.set_streaming_client_observer(observer)\n")),(0,i.mdx)("h4",{id:"5-start-subscribing-and-listen-to-the-live-stream"},"5. Start subscribing and listen to the live stream"),(0,i.mdx)("p",null,"The client begins listening for incoming streaming data from the subscribed data types."),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"streaming_client.subscribe()\n")),(0,i.mdx)("h4",{id:"6-visualize-the-live-stream"},"6. Visualize the live stream"),(0,i.mdx)("ul",null,(0,i.mdx)("li",{parentName:"ul"},"RGB and SLAM images are visualized in separate windows using OpenCV. The images are processed and displayed the streaming stops or the application quit. We rotate the image and stack the SLAM images so that they are shown in a single window.")),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"while not quit_keypress():\n    # Render the RGB image\n    if aria.CameraId.Rgb in observer.images:\n        rgb_image = np.rot90(observer.images[aria.CameraId.Rgb], -1)\n        rgb_image = cv2.cvtColor(rgb_image, cv2.COLOR_BGR2RGB)\n        cv2.imshow(rgb_window, rgb_image)\n        del observer.images[aria.CameraId.Rgb]\n\n    # Stack and display the SLAM images\n    if (\n        aria.CameraId.Slam1 in observer.images\n        and aria.CameraId.Slam2 in observer.images\n    ):\n        slam1_image = np.rot90(observer.images[aria.CameraId.Slam1], -1)\n        slam2_image = np.rot90(observer.images[aria.CameraId.Slam2], -1)\n        cv2.imshow(slam_window, np.hstack((slam1_image, slam2_image)))\n        del observer.images[aria.CameraId.Slam1]\n        del observer.images[aria.CameraId.Slam2]\n")),(0,i.mdx)("admonition",{type:"note"},(0,i.mdx)("p",{parentName:"admonition"},"Cameras on Aria glasses are installed sideways. The visualizer rotates the raw image data for a more natural view.")),(0,i.mdx)("h3",{id:"7-unsubscribe-from-the-stream-and-free-resources"},"7. Unsubscribe from the stream and free resources"),(0,i.mdx)("ul",null,(0,i.mdx)("li",{parentName:"ul"},"Unsubscribing stops the client from listening to streaming data and cleans up resources.")),(0,i.mdx)("pre",null,(0,i.mdx)("code",{parentName:"pre",className:"language-python"},"streaming_client.unsubscribe()\n")))}p.isMDXComponent=!0}}]);