package ru.khalkechev.springsecuritycrud.dao;

import ru.khalkechev.springsecuritycrud.model.Role;

import java.util.Set;

public interface RoleDAO {
    Role save(Role role);

    void deleteRoleById(long id);

    Role update(Role role);

    Role getRoleById(long id);

    Set<Role> getSetOfRoles();
}
