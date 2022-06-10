package spring.securitycore.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.securitycore.domain.entity.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
    Account findByUsername(String username);
}
