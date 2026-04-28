package springapp.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.UUID;
import java.lang.reflect.Method;

@Controller
public class SsoController {

    private static final String SECRET_KEY = "MySuperSecretKeyForSsoCourse2024";

    @RequestMapping("/sso/gotoHr.html")
    public String gotoHr(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession();
            String username = null;

            // --- GIẢI PHÁP LẤY USERNAME TỪ SESSION (TRIỆT ĐỂ) ---
            if (request.getUserPrincipal() != null) {
                username = request.getUserPrincipal().getName();
            }

            if (username == null) {
                java.util.Enumeration<String> attributeNames = session.getAttributeNames();
                while (attributeNames.hasMoreElements()) {
                    String attrName = attributeNames.nextElement();
                    Object obj = session.getAttribute(attrName);
                    if (obj != null) {
                        username = tryGetUsernameFromObject(obj);
                        if (username != null && !username.trim().isEmpty()) {
                            break; 
                        }
                    }
                }
            }

            if (username == null || username.trim().isEmpty()) {
                return "redirect:/admin/login.html?error=NotLoggedIn";
            }

            // Encode(user + timer)
            long exp = (System.currentTimeMillis() / 1000) + 300; // 300 giây
            String jti = UUID.randomUUID().toString();
            
            // Payload chứa user và timer
            String payloadJson = String.format("{\"sub\":\"%s\",\"exp\":%d,\"jti\":\"%s\"}", username, exp, jti);
            
            byte[] payloadBytes = payloadJson.getBytes("UTF-8");
            String payloadB64 = javax.xml.bind.DatatypeConverter.printBase64Binary(payloadBytes)
                                    .replace("+", "-").replace("/", "_").replace("=", "");

            String signature = createHMAC(payloadB64, SECRET_KEY);
            String token = payloadB64 + "." + signature;

            // Chuyển hướng sang HR (Port 19335)
            return "redirect:http://localhost:19335/Sso/Consume?token=" + token;

        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/admin/employee/list.html?error=SsoExportFailed";
        }
    }

    private String tryGetUsernameFromObject(Object obj) {
        if (obj instanceof String) return (String) obj;
        String[] methodNames = {"getUsername", "getName", "getEmail", "getUserName"};
        for (String methodName : methodNames) {
            try {
                Method method = obj.getClass().getMethod(methodName);
                Object result = method.invoke(obj);
                if (result instanceof String) return (String) result;
            } catch (Exception e) {}
        }
        return null;
    }

    private String createHMAC(String data, String key) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] hash = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
        return javax.xml.bind.DatatypeConverter.printBase64Binary(hash)
                    .replace("+", "-").replace("/", "_").replace("=", "");
    }
}