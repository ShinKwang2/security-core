package spring.securitycore.domain.entity;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
@Getter
@EqualsAndHashCode(of = "id")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class Account {

    @Id @GeneratedValue
    private Long id;

    @Column
    private String username;
    @Column
    private String password;

    @Column
    private String email;

    @Column
    private int age;

    @Column
    private String role;

    @Builder
    public Account(String username, String password, String email, int age, String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.role = role;
    }

    public void encodePassword(String password) {
        this.password = password;
    }
}
