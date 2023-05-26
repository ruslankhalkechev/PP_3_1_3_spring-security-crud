package ru.khalkechev.springsecuritycrud.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.khalkechev.springsecuritycrud.dao.UserDAO;
import ru.khalkechev.springsecuritycrud.model.User;

@Service
public class CustomUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
    private final UserDAO userDAO;

    @Autowired
    public CustomUserDetailsService(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    public User findByUserName(String username) {
        return userDAO.findByUserName(username);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.findByUserName(username);
        if (user == null) {
            throw new UsernameNotFoundException("User -" + username + "- not found");
        }
        return user;
    }
}
