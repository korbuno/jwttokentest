import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.json.simple.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.Map;

public class JwtTokenTestMain {
    public static void main(String[] args) {

        JSONObject json = new JSONObject();
        Map<String, String> map = new HashMap<String, String>();

        // Header 작성

        map.put("typ", "JWT");
        map.put("alg", "HS256");
        json.putAll(map);
        String header = base64Encoding(json);
        System.out.println("header : " + header);
        clearMemory(json, map);

        // Payload 작성

        map.put("iss", "korbuno");
        map.put("exp", "1485270000000");
        map.put("localhost:8080", "true");
        map.put("userId", "1234");
        map.put("username", "korbuno");
        json.putAll(map);
        String payload = base64Encoding(json);
        System.out.println("payload : " + payload);
        clearMemory(json, map);

        // Signature 작성

        String signature = "";
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec("secret".getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            signature = Base64.encode(mac.doFinal((header + "." + payload).getBytes())).replaceAll("=", "");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("signature : " + signature);

        // jwtToken 작성

        String jwtToken = header + "." + payload + "." + signature;
        System.out.println("jwtToken : " + jwtToken);
    }

    private static String base64Encoding(JSONObject json) {
        return Base64
                .encode(json
                        .toJSONString()
                        .getBytes()
                ).replaceAll("=", "");
    }

    private static void clearMemory(JSONObject json, Map map) {
        json.clear();
        map.clear();
    }
}
