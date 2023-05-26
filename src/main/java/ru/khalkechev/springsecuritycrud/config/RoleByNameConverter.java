package ru.khalkechev.springsecuritycrud.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import ru.khalkechev.springsecuritycrud.dao.RoleDAO;
import ru.khalkechev.springsecuritycrud.model.Role;

@Component
public class RoleByNameConverter implements Converter<String, Role> {
    private final RoleDAO roleDAO;

    @Autowired
    public RoleByNameConverter(RoleDAO roleDAO) {
        this.roleDAO = roleDAO;
    }

    @Override
    public Role convert(String id) {
        return roleDAO.getRoleById(Long.valueOf(id));
    }
}
