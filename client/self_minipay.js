Java.perform(function(){
    try{
    const SSLcontext=Java.use('javax.net.ssl.SSLContext');
    const init=SSLcontext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    )
    init.implementation=function(km,tm,sr){
        console.log("[+]远方阿飞");
        return init.call(this,km,null,sr);
    }
        console.log("[TLS]hook ok");
    }catch(e){
        console.log("[TLS]hook 未生效"+e);
}
    try{
        const p=Java.use('com.minipay.pro.runtime.p');
        const c=p.c.overload();
        c.implementation=function(){
            const real=c.call(this);
            console.log("原c结果为:"+real);
            return real;
        }
    }catch(e){
        console.log("没能看到c的输出，看看啥原因。"+e);
    }//其实a是没有必要的，但是a方法的hook是为了看黄金向量， 用行为判断结果操作很重要！！
    try{
       const NB=Java.use("com.minipay.pro.security.NativeBridge");
       NB.b.overloads.forEach(function(ol,idx){
           ol.implementation=function(){
            const args=[];
            for(let i =0;i<arguments.length;i++) args.push(String(arguments[i]));
            console.log("b()方法被调用了"+JSON.stringify(args));
            const ret=ol.apply(this,arguments);
            console.log("b()方法返回的真实值"+ret);
            return ret;
           }
       })
    }catch(e){
        console.log("b()方法出错了"+e);
    }
        try{
        const NB=Java.use("com.minipay.pro.security.NativeBridge");
        NB.a.overloads.forEach(function(ol,lim){
            ol.implementation=function(){
                const args=[];
                for(let i=0;i<arguments.length;i++) args.push(String(arguments[i]));
                const ret=ol.apply(this,arguments);
                console.log("[a方法]真实的"+JSON.stringify(args));
                console.log("ret="+ret);
                return ret;
            }
        }
        )
    }catch(e){
        console.log("a()方法hook出错"+e);
    }
    try{
        const NB=Java.use("com.minipay.pro.security.NativeBridge");
        NB.d.overloads.forEach(function(ol,idx){
            ol.implementation=function(){
                console.log("[d方法]");
                const args=[];
                for(let i =0;i<arguments.length;i++) args.push(String(arguments[i]));
                console.log("第"+idx+"版的参数为"+JSON.stringify(args));
                const ret=ol.apply(this,arguments);
                console.log("真实的值为:"+String(ret));
                return ret;
            }
        })
    }catch(e){
        console.log("d方法未执行"+e);
    }


    

});
function installCheck(base){
    Interceptor.attach(base.add(0x3EB8),{
            onEnter: function (args) {
                 console.log("[sig] 进来了, lr=" + this.context.lr.sub(base));
                 for (let i = 0; i < 5; i++) {   // 按你分析的实际参数个数循环
                     try {
                         const p = args[i];
                         let line = "arg" + i + " = " + p;
                         // 试着按字符串读一下,读不出来就打印原始指针
                         try {
                             const s = p.readCString();
                             if (s && s.length > 0 && s.length < 300) line += "  =>  \"" + s + "\"";
                         } catch (e) {}
                         console.log(line);
                     } catch (e) {
                         console.log("arg" + i + " 读取失败: " + e);
                     }
                 }
             },
            
            onLeave:function(retval){
                try{console.log("对比一下看跟body入参一不一样"+retval);
            return retval;
        }catch(e){
            console.log("hook 返回值失败:"+e);
        }
            
        }
    })
}
function installNative(base){
    Interceptor.attach(base.add(0x2BA4),{
        onLeave:function(retval){
            console.log("电表的初始值为:"+retval);
            retval.replace(0);
            console.log("电表归零了");
        }
    });
        console.log("retval hook over!");
    };
function installFreeProbes(base) {
   Interceptor.attach(base.add(0x3EB8),{
    onEnter:function(args){
         const lr = this.context.lr;                      // ← 改这里
         if (!lr.equals(base.add(0x1D54))) return;
        console.log("胡可 格式串生效！");
        for(let i=0;i<5;i++){
            try {
                         const p = args[i];
                         let line = "arg" + i + " = " + p;
                         // 试着按字符串读一下,读不出来就打印原始指针
                         try {
                             const s = args[0].readCString();
                             console.log("================================");
                             console.log('输入="' + s + '"  长度=' + s.length + '  inLen(arg1)=' + args[1].toInt32());
                         } catch (e) {console.log("你得改回去了:"+e);}
                         console.log(line);
                     } catch (e) {
                         console.log("arg" + i + " 读取失败: " + e);
                     }
        }
    }
   })
}
const timer = setInterval(function () {
    const m = Process.findModuleByName('libmpguard.so');
    if (m) {
        clearInterval(timer);
        installNative(m.base);
        installFreeProbes(m.base); 
        installCheck(m.base);
    }
}, 100);
