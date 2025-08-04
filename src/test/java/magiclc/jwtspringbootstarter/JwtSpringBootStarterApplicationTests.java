package magiclc.jwtspringbootstarter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest(classes = TestApplication.class)
@Import(TestApplication.class)
class JwtSpringBootStarterApplicationTests {

    @Test
    void contextLoads() {
        // 测试Spring上下文是否能正常加载
    }

}
