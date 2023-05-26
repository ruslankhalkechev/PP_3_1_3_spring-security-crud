package ru.khalkechev.springsecuritycrud.model;


import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;


@Entity
@Table(name = "user")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @NotEmpty(message = "Поле `Логин` не должно быть пустым")
    @Size(min = 3, max = 20, message = "Логин должен содержать не менее 3 и не более 20 символов")

    @Column(name = "name", unique = true)
    private String name;

    @NotEmpty(message = "Поле `Пароль` не должно быть пустым")
    @Size(min = 3, message = "Пароль должен содержать не менее 3 символов")

    @Column(name = "password")
    private String password;

    @NotEmpty(message = "Поле `Имя пользователя` не должно быть пустым")
    @Size(min = 2, max = 20, message = "Имя должно содержать не менее 2 символов и не более 20")

    @Column(name = "firstName")
    private String firstName;

    @NotEmpty(message = "Поле `Фамилия` не должно быть пустым")
    @Size(min = 2, max = 20, message = "Фамилия должна содержать не менее 2 символов и не более 20")

    @Column(name = "surname")
    private String surname;

    @Min(value = 18, message = "Возраст не должен быть менее 18 лет ")

    @Column(name = "age")
    private byte age;

    @NotEmpty(message = "Поле `E-mail` не должно быть пустым")
    @Email(message = "E-mail должен быть валидным")

    @Column(name = "email")
    private String email;

    @NotEmpty(message = "Должна быть выбрана хотя бы одна роль")
    @ManyToMany(cascade = CascadeType.PERSIST)
    @JoinTable(
            name = "user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    Set<Role> roles = new HashSet<>();

    public User() {
    }

    public User(String name, String password, String firstName, String surname, byte age, String email) {
        this.name = name;
        this.password = password;
        this.firstName = firstName;
        this.surname = surname;
        this.age = age;
        this.email = email;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.getRoles().stream().map(role ->
                new SimpleGrantedAuthority(role.getAuthority())).collect(Collectors.toSet());
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return getName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public byte getAge() {
        return age;
    }

    public void setAge(byte age) {
        this.age = age;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void addRole(Role role) {
        this.roles.add(role);
        role.getUsers().add(this);
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
        role.getUsers().remove(this);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", password='" + password + '\'' +
                ", firstName='" + firstName + '\'' +
                ", surname='" + surname + '\'' +
                ", age=" + age +
                ", salary=" + email +
                '}';
    }
}
