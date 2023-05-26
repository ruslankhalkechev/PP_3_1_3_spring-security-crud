package ru.khalkechev.springsecuritycrud.service;

import ru.khalkechev.springsecuritycrud.model.Role;
import ru.khalkechev.springsecuritycrud.model.User;

import java.util.List;
import java.util.Set;

public interface UserService {
    User save(User user);

    void deleteUserById(long id);

    User updateById(User user, long id);

    User getUserById(long id);

    List<User> getListOfUsers();

    Set<Role> getSetOfRoles();

}
