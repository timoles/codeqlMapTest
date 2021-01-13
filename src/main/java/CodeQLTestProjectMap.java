import java.util.HashMap;
import java.util.Map;

public class CodeQLTestProjectMap {

	public static void main(String[] args) {
		
        Map<String, Object> env = new HashMap<>();
        env.put("test1", "test1");
        env.put("test2", "test2");
        env.put("secret", "secret");
        env.put("test3", "test3");
        new TestConstructor(null, env);
	}
}

