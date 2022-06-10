package spring.securitycore.domain.dto;

import lombok.Data;
import spring.securitycore.domain.entity.Account;

@Data
public class AccountDto {

    private String username;
    private String password;
    private String email;
    private int age;
    private String role;

    public Account toEntity() {
        return Account.builder()
                .username(this.username)
                .password(this.password)
                .email(this.email)
                .age(this.age)
                .role(this.role)
                .build();
    }
}
