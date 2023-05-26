package ru.khalkechev.springsecuritycrud.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import ru.khalkechev.springsecuritycrud.dao.UserDAO;
import ru.khalkechev.springsecuritycrud.model.User;

@Component
public class UserValidator implements Validator {
    private final UserDAO userDAO;

    @Autowired
    public UserValidator(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        User user = (User) target;
        if (userDAO.findByUserName(user.getName()) != null) {
            errors.rejectValue("name", "", "Такой логин уже существует");
        }
    }
}
