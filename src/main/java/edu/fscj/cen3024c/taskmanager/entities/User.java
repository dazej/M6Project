// User.java
// D. Singletary
// 9/10/25
// User entity for task manager application

package edu.fscj.cen3024c.taskmanager.entities;

import jakarta.persistence.*;
import java.util.Set;

@Entity
@Table(name = "users") // avoid 'user' in postgreSQL
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true)
    private String username;

    @ManyToMany(mappedBy = "users")
    private Set<Task> tasks;

    @Column(nullable = false)
    private String salt;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    // Constructors
    public User() {}

    public User(String username, String password) {
        this.username = username;
        this.passwordHash = password;
    }


    // Getters & setters
    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return passwordHash; }
    public void setPassword(String password) { this.passwordHash = password; }
    

    public Set<Task> getTasks() { return tasks; }
    public void setTasks(Set<Task> tasks) { this.tasks = tasks; }

    public void setSalt(String salt) { this.salt = salt; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
}
