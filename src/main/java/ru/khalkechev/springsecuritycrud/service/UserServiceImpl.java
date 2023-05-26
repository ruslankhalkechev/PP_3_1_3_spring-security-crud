package ru.khalkechev.springsecuritycrud.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.khalkechev.springsecuritycrud.dao.RoleDAO;
import ru.khalkechev.springsecuritycrud.dao.UserDAO;

import ru.khalkechev.springsecuritycrud.model.Role;
import ru.khalkechev.springsecuritycrud.model.User;

import java.util.List;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService {

    private final UserDAO userDAO;
    private final RoleDAO roleDAO;

    @Autowired
    public UserServiceImpl(UserDAO userDAO, RoleDAO roleDAO) {
        this.userDAO = userDAO;
        this.roleDAO = roleDAO;
    }


    @Override
    @Transactional
    public User save(User user) {
        userDAO.save(user);
        return user;
    }

    @Override
    @Transactional
    public void deleteUserById(long id) {
        User user = userDAO.getUserById(id);
        userDAO.delete(user);
    }

    @Override
    @Transactional
    public User updateById(User updatedUser, long id) {
        User userToBeUpdated = getUserById(id);

        userToBeUpdated.setName(updatedUser.getName());
        userToBeUpdated.setPassword(updatedUser.getPassword());
        userToBeUpdated.setFirstName(updatedUser.getFirstName());
        userToBeUpdated.setSurname(updatedUser.getSurname());
        userToBeUpdated.setAge(updatedUser.getAge());
        userToBeUpdated.setEmail(updatedUser.getEmail());
        userToBeUpdated.setRoles(updatedUser.getRoles());

        userDAO.update(userToBeUpdated);
        return userToBeUpdated;
    }

    @Override
    public User getUserById(long id) {
        return userDAO.getUserById(id);
    }

    @Override
    public List<User> getListOfUsers() {
        return userDAO.getListOfUsers();
    }

    @Override
    public Set<Role> getSetOfRoles() {
        return roleDAO.getSetOfRoles();
    }
}