package spring.securitycore.service.imple;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.securitycore.domain.entity.Account;
import spring.securitycore.repository.UserRepository;
import spring.securitycore.service.UserService;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service("userService")
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {

        userRepository.save(account);
    }
}
