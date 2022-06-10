package spring.securitycore.security.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import spring.securitycore.domain.entity.Account;

import java.util.Collection;

public class AccountContext extends User {

    private final Account account;  //나중에 참조할 수 있도록 필드 선언

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
