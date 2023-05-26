package ru.khalkechev.springsecuritycrud.dao;

import ru.khalkechev.springsecuritycrud.model.User;

import java.util.List;

public interface UserDAO {
    User save(User user);

    void delete(User user);

    void deleteUserById(long id);

    User update(User user);

    User getUserById(long id);

    List<User> getListOfUsers();

    User findByUserName(String username);
}
