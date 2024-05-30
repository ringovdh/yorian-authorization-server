package be.yorian.entity;

public record newUser(
        String email,
        String password,
        String repeatPassword) {
}
