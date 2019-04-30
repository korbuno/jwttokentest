개요

API Key 방식

여러 애플리케이션이 나뉘어져 분할되어 있을 때(소위 MSA), 쉽게 묶어서 관리하고 통합하는 방법은 공용 DBMS를 이용하는 것이다.
하지만 만약, DB의 스키마를 아주 작게라도 한번 변경한다면 여러 애플리케이션이 문제를 일으킬 수 있다.
그래서 등장한 방식이 API서버이다. 즉, 여러 애플리케이션 요청에 따라 DB에 주도적으로 접근하는 애플리케이션을 만들어 낸 것이다.
"사용자 정보든, 뭐든, 필요로 하는 녀석이 API로 요청해라. 그럼 내가 알아서 찾아줄게."

 
그 다음으로, 어떤 클라이언트에서 찌르는지 관련된 정보가 필요했다. 그래서 인증(Authentication)과 인가(Authorization)가 나타나게 된 것이다.

인증 : "나 맞아"
인가 : "나 반장이야"

인증과 인가를 관리하기 위해 가장 먼저 등장한, 가장 보편적으로 쓰이는 기술이 바로 API Key 방식이다.


3번 Request UserInfo 과정에서 자신을 증명하기 위해, API Key라는 허가증을 같이 보낸다.
인증 저장소(Resource)는 본인이 갖고있는 API Key와 맞춰보고, 확인한 후에 반응을 결정한다.


위 방식은 괜찮은 방법일 수 있지만, API Key가 항상 클라이언트와 저장소측이 동기화 되어있어야 한다.
또한, 키가 유출될 가능성을 고려해, 주기적으로 키 값을 변경해야 되는데, 결과적으로 관리가 힘들어질 것이다.
이런 단점을 극복하기 위해 나타난 것이 바로 OAuth2이다.


OAuth2
애플리케이션과 애플리케이션이 하는 약속에서, 더 나아가 사용자가 적당히 개입하는 방식이 도입되었다.

요청하는 서버(클라이언트), 요청받는 서버(Resource), 인증하는 서버(OAuth2)로 세분화되었다.



사용자가 로그인을 시도한다. 여기서 Client는 자신에게 미리 로그인이 되어있는지를 확인한다. 안되어있다면 파란 선을 따라간다.
즉, 인증서버에 사용자를 돌려보낸다(Redirect).
인증서버는 사용자로부터 Authorize요청을 받아(윗줄1번) 이 사용자가 회원인지, 인증서버에 로그인 되어 있는지를 확인한다.
인증을 거쳤다면, 이 사용자가 최초로 인가를 요청한 서버에 대한 사용의사(권한)가 있는지 확인한다.

이 과정을 Grant라고 부른다.

Grant
인가(Authorization)와는 조금 다르다. 인가는 서비스 제공자의 입장에서 사용자의 권한을 보는 것이지만, Grant는 사용자가 자신의 인증 정보(이름, 메일주소, 전화번호 등)를 자신이 사용하려는 말지를 결정하는 과정이다.
만약 사용자가 Grant한 상태가 아니라면, 사용자에게 Grant를 요청하게 된다. 즉, 사용자 개입이 일어나게 된다.

"업무 서버(Client)가 내 인증 정보를 읽을 수 있도록 허용해."

Grant가 완료 된다면, 인가 코드를 Datastore에 저장하고(1.4), 다시 Authorize에서 업무 서버(Client)에 인가 코드를 전달한다.

업무 서버는 인가 코드를 이용하여 사용자의 인증 정보에 접근할 수 있다. 아주 짧은 시간동안 이지만.
코드는 보안을 위해 유효기간이 굉장히 짧으며, 이 기간 안에 업무 서버는 Access Token을 인증 서버에게 받아내야한다.
Access Token은 위에 API Key와 유사하게 사용된다.

인증 서버는 인가 코드를 Datastore에 저장된 정보와 일치하는지 확인하고(2.1), Access Token을 만들어 Datastore에 저장하고 업무 서버에 건네준다.  긴 유효시간을 갖고 있다는 점이 중요하다.

드디어 업무 서버가 Access Token을 받았다. 이제 저장소 서버에 당당하게 자료를 요청하고 받아낼 수 있게 된 것이다.(3)
하지만, 저장소 서버또한 만만치 않은데, Access Token 내용을 간접적으로 검사하기 때문이다.
검사하는 이유는 Access Token 자체가 별 의미 없는 복잡한 문자열 값이라서다.

실제로 OAuth2는 훌륭한 방법이다. 조금 복잡하긴 하지만, 키 분실 위협이나 보안 관점에서는 많은 부분 개선되었지만 아직까지 만족스럽지 못한 부분 또한 있다.

JWT (JSON Web Token)

그러다가 등장한 것이 JWT이다. 이 규약은 인증 흐름에 대한 규약이 아닌, Token 작성에 대한 규약이다.
앞서 말한듯이, Access Token은 별 의미 없는 복잡한 문자열 값으로 이루어져, Token 값에 대한 진위나 유효성을 매번 검사해야한다.
JWT는 Token값 안에 위조여부 확인을 위한 값, 유효성 검증을 위한 값, 인증정보 자체를 담아 제공한다.

즉, Token 확인 단계를 인증 서버에게 묻지 않고서도 할 수 있도록 만든 것이다.

jwt
JWT 토큰은 위와 같이 3단 구조로 이루어져 있다.

헤더(header)

typ : 토큰의 타입(ex. JWT)
alg : 해싱 알고리즘으로 보통 SHA256 혹은 RSA 방법이 사용된다.

내용(payload)

토큰에 담을 내용이며, 내용의 한 조각을 클레임(Claim)이라고 부른다.
즉, 토큰에는 여러 개의 클레임으로 이루어질 수 있다.

클레임의 종류

등록된(registered) 클레임

토큰에 대한 정보들을 미리 담아 규정하는 방식, 이미 정해진 클레임들
등록된 클레임의 사용은 모두 선택사항(optional)이다.

iss : 토큰 발급자
sub : 토큰 제목
aud : 토큰 대상자
exp : 만료 기간
nbf : 시작되는 기간
iat : 토큰이 발급된 시간
jti : JWT고유 식별자

공개(public) 클레임

공개된 클레임은 중복을 방지하는 값으로 이루어지며 URI형태를 갖는다.
{
     "localhost:8080" : true
}
비공개(private) 클레임

비공개 클레임은 클라이언트와 서버 양측간에 협의되어 사용되는 클레임 이름들이다. 프로퍼티 명이 중복되지 않게 유의해야 한다.
{
     "username" : "korbuno"
}
예제 payload 클레임

 {
     "iss" : "korbuno",
     "exp" : "1485270000000",
     "localhost:8080" : true,
     "userId" : "1234",
     "username" : "korbuno"
}
위 클레임은 2개의 등록된 클레임, 1개의 공개 클레임, 2개의 비공개 클레임으로 작성되어 있다.

서명(signature)

헤더(header)의 인코딩 값과 정보(payload)의 인코딩 값을 합친 후, 비밀키로 해쉬를 하여 생성한다.

구조 : secretKeyHashing(encode(header) + "." + encode(payload))


예제 코드

링크 : https://github.com/korbuno/jwttokentest

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

참고 : "="는 URI내에서 사용시 안전하지 않을 수 있기 때문에 전부 없애는 것이 맞다. 또한, 없애도 별 문제는 없다.



결과 확인

https://jwt.io/ 에서 확인해 보았다.

jmsight > OAuth2, JWT > image2019-4-30_11-32-7.png

변경된 구조


이제 Token안에 인증정보, 사용자 정보, 발급자 정보와 서명, 유효기간 등을 포함하였기 때문에 OAuth2에서의 3번대 그림이 완전히 사라져버렸다.
결과적으로 Token을 받고나면, "이 신분증이 맞나요?" 라고 확인할 과정이 필요가 없어진 것이다.


참조한 링크

https://www.sauru.so/blog/basic-of-oauth2-and-jwt/
https://velopert.com/2389

