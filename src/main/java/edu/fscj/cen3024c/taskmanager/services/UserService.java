// UserService.java
// D. Singletary
// 11/20/25
// User service for task manager application

package edu.fscj.cen3024c.taskmanager.services;

import edu.fscj.cen3024c.taskmanager.dto.CreateUserRequestDTO;
import edu.fscj.cen3024c.taskmanager.dto.UpdateUserRequestDTO;
import edu.fscj.cen3024c.taskmanager.dto.UserDTO;
import edu.fscj.cen3024c.taskmanager.entities.Task;
import edu.fscj.cen3024c.taskmanager.entities.User;
import edu.fscj.cen3024c.taskmanager.exceptions.UserNotFoundException;
import edu.fscj.cen3024c.taskmanager.repositories.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private static final String ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int ITERATIONS = 1_300_000;   // OWASP guidance for PBKDF2-HMAC-SHA1
    private static final int KEY_LENGTH_BITS = 160;    // SHA-1 output size; longer adds cost without extra strength
    private static final int SALT_LENGTH_BYTES = 16;   // 128-bit salt (NIST SP 800-132 minimum)

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // ===== CRUD Methods with DTO conversion =====

    @Transactional(readOnly = true)
    public List<UserDTO> findAll() {
        return userRepository.findAll()
                .stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDTO findById(Integer id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
        return convertToDTO(user);
    }

    // Helper to return raw entity (for updates/deletes)
    @Transactional(readOnly = true)
    public User findByIdEntity(Integer id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    // ===== Create / Update using request DTOs =====

    @Transactional
    public UserDTO createUser(CreateUserRequestDTO request) {
        String salt = generateSalt();
        String hash;
        try {
            hash = hashPassword(request.getPassword(), salt);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
        User user = new User();
        user.setUsername(request.getUsername());
// NEW FIELDS ON ENTITY (you must add these in User.java)
        user.setSalt(salt);
        user.setPasswordHash(hashPassword(request.getPassword(), salt));
        User savedUser = userRepository.save(user);
        return convertToDTO(savedUser);
    }
    @Transactional
    public UserDTO updateUser(Integer id, UpdateUserRequestDTO request) {
        User existingUser = findByIdEntity(id);
        existingUser.setUsername(request.getUsername());

// Always re-hash since password is required
        String salt = generateSalt();
        String hash;
        try {
            hash = hashPassword(request.getPassword(), salt);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
        existingUser.setSalt(salt);
        existingUser.setPasswordHash(hash);
        User updatedUser = userRepository.save(existingUser);
        return convertToDTO(updatedUser);
    }

    private String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /** Derives a PBKDF2WithHmacSHA1 hash of the password, Base64-encoded for storage. */
    private String hashPassword(String password, String salt) {
        char[] passwordChars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(
                passwordChars,
                Base64.getDecoder().decode(salt),
                ITERATIONS,
                KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Error hashing password", e);
        } finally {
            spec.clearPassword();                         // wipe password from memory
            java.util.Arrays.fill(passwordChars, '\0');
        }
    }


    public void deleteById(Integer id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException(id);
        }
        userRepository.deleteById(id);
    }

    // ===== Entity to DTO Conversion =====
    public UserDTO convertToDTO(User user) {
        Set<String> taskTitles = (user.getTasks() != null)
                ? user.getTasks().stream()
                .map(Task::getTitle)
                .collect(Collectors.toSet())
                : Set.of();

        return new UserDTO(
                user.getId(),
                user.getUsername(),
                taskTitles
        );
    }
}
