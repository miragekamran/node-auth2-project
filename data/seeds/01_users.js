// pre-hashed password for "abc12345"
const hashedPassword =
    "$2a$14$qHqCbXUImiBOgXlFNX47wuA7uFWNGNAZutYLvOeye9eotewGlfYV6";

exports.seed = async function (knex) {
    await knex("users").insert([
        { id: 1, username: "janedoe", password: hashedPassword },
        { id: 2, username: "johndoe", password: hashedPassword },
        { id: 3, username: "jahandoe", password: hashedPassword },
        { id: 4, username: "johanedoe", password: hashedPassword }
    ]);
};
