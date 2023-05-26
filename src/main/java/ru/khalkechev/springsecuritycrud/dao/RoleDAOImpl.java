package ru.khalkechev.springsecuritycrud.dao;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;
import ru.khalkechev.springsecuritycrud.model.Role;

import java.util.Set;
import java.util.stream.Collectors;

@Repository
public class RoleDAOImpl implements RoleDAO {
    @PersistenceContext
    EntityManager entityManager;

    @Override
    public Role save(Role role) {
        entityManager.persist(role);
        return role;
    }

    @Override
    public void deleteRoleById(long id) {
        Role role = entityManager.find(Role.class, id);
        entityManager.remove(role);
    }

    @Override
    public Role update(Role role) {
        entityManager.merge(role);
        return role;
    }

    @Override
    public Role getRoleById(long id) {
        return entityManager.find(Role.class, id);
    }

    @Override
    public Set<Role> getSetOfRoles() {
        return entityManager.createQuery("FROM Role role ORDER BY role.id", Role.class).getResultStream().collect(Collectors.toSet());
    }
}
