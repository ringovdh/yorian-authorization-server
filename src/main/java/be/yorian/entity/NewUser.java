package be.yorian.entity;

public record NewUser(
        String email,
        String password,
        String repeatPassword) {
}
