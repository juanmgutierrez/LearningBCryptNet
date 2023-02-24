// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

// Generate Salt
string salt1 = BCrypt.Net.BCrypt.GenerateSalt();
string salt2 = BCrypt.Net.BCrypt.GenerateSalt(workFactor: 12);
string salt3 = BCrypt.Net.BCrypt.GenerateSalt(workFactor: 11, bcryptMinorRevision: 'a');

Console.WriteLine($"Salt 1: {salt1}");
Console.WriteLine($"Salt 2: {salt2}");
Console.WriteLine($"Salt 3: {salt3}\n");


// HashPassword
string passwordHash1 = BCrypt.Net.BCrypt.HashPassword("password");
string passwordHash2 = BCrypt.Net.BCrypt.HashPassword("password", @"$2a$11$0fOoYZ8ITKO/..8lZrGRIu"); // Not recommended. Salt: "Best generated using BCrypt.Net.BCrypt."
string passwordHash3 = BCrypt.Net.BCrypt.HashPassword("password", salt2);
string passwordHash4 = BCrypt.Net.BCrypt.HashPassword("password", workFactor: 11);

Console.WriteLine($"Password Hash 1: {passwordHash1}");
Console.WriteLine($"Password Hash 2: {passwordHash2}");
Console.WriteLine($"Password Hash 3: {passwordHash3}");
Console.WriteLine($"Password Hash 4: {passwordHash4}\n");


// Get Hash Info
BCrypt.Net.HashInformation? hashInformation = BCrypt.Net.BCrypt.InterrogateHash(passwordHash3); // Throws exception when is not a valid hash

Console.WriteLine("Hash information:");
Console.WriteLine($"Original Hash: {passwordHash3}");
Console.WriteLine($"Settings: {hashInformation.Settings}");
Console.WriteLine($"Raw Hash: {hashInformation.RawHash}");
Console.WriteLine($"Version: {hashInformation.Version}");
Console.WriteLine($"Work Factor: {hashInformation.WorkFactor}\n");


// Password Needs Rehash
bool needsRehash1 = BCrypt.Net.BCrypt.PasswordNeedsRehash(hash: passwordHash1, newMinimumWorkLoad: 10);
bool needsRehash2 = BCrypt.Net.BCrypt.PasswordNeedsRehash(hash: passwordHash1, newMinimumWorkLoad: 11);
bool needsRehash3 = BCrypt.Net.BCrypt.PasswordNeedsRehash(hash: passwordHash1, newMinimumWorkLoad: 12);

Console.WriteLine($"Needs Rehash (newMinimumWorkLoad = 10): {needsRehash1}");
Console.WriteLine($"Needs Rehash (newMinimumWorkLoad = 11): {needsRehash2}");
Console.WriteLine($"Needs Rehash (newMinimumWorkLoad = 12): {needsRehash3}\n");


// Verify
bool verifyWithValidPassword = BCrypt.Net.BCrypt.Verify("password", hash: passwordHash1);
bool verifyWithInvalidPassword = BCrypt.Net.BCrypt.Verify("invalidPassword", hash: passwordHash1);

Console.WriteLine($"Verify with valid password: {verifyWithValidPassword}");
Console.WriteLine($"Verify with invalid password: {verifyWithInvalidPassword}\n");


// Validate and replace password
Console.WriteLine("Validate and Replace password:");
try
{
    string newPasswordForValidateAndReplaceWithInvalidPassword = BCrypt.Net.BCrypt.ValidateAndReplacePassword("invalidPassword", currentHash: passwordHash1, "newPassword");
    Console.WriteLine($"New password for Validate and Replace Password (with invalid password): {newPasswordForValidateAndReplaceWithInvalidPassword}");
}
catch (BCrypt.Net.BcryptAuthenticationException bcryptAuthenticationException)
{
    Console.WriteLine($"BcryptAuthenticationException - {bcryptAuthenticationException.Message}");
}

string newPasswordForValidateAndReplaceWithValidPassword = BCrypt.Net.BCrypt.ValidateAndReplacePassword("password", currentHash: passwordHash1, "newPassword");
Console.WriteLine($"New password for Validate and Replace Password (with valid password): {newPasswordForValidateAndReplaceWithValidPassword}");

// By default, this method doesn't accept a workFactor lower than the one in the previous hashed password
string newPasswordForValidateAndReplaceWithLowerWorkFactor = BCrypt.Net.BCrypt.ValidateAndReplacePassword("password", currentHash: passwordHash1, "newPassword", workFactor: 10);
string newPasswordForValidateAndReplaceWithEqualWorkFactor = BCrypt.Net.BCrypt.ValidateAndReplacePassword("password", currentHash: passwordHash1, "newPassword", workFactor: 11);
string newPasswordForValidateAndReplaceWithHigherWorkFactor = BCrypt.Net.BCrypt.ValidateAndReplacePassword("password", currentHash: passwordHash1, "newPassword", workFactor: 12);
BCrypt.Net.HashInformation? hashInfoForLowerWorkFactor = BCrypt.Net.BCrypt.InterrogateHash(newPasswordForValidateAndReplaceWithLowerWorkFactor);
BCrypt.Net.HashInformation? hashInfoForEqualWorkFactor = BCrypt.Net.BCrypt.InterrogateHash(newPasswordForValidateAndReplaceWithEqualWorkFactor);
BCrypt.Net.HashInformation? hashInfoForHigherWorkFactor = BCrypt.Net.BCrypt.InterrogateHash(newPasswordForValidateAndReplaceWithHigherWorkFactor);
Console.WriteLine($"New password for Validate and Replace Password (with lower work factor): {newPasswordForValidateAndReplaceWithLowerWorkFactor}");
Console.WriteLine($"New password for Validate and Replace Password (with equal work factor): {newPasswordForValidateAndReplaceWithEqualWorkFactor}");
Console.WriteLine($"New password for Validate and Replace Password (with higher work factor): {newPasswordForValidateAndReplaceWithHigherWorkFactor}");
Console.WriteLine($"Work factor for Validate and Replace Password (with lower work factor): {hashInfoForLowerWorkFactor.WorkFactor}");
Console.WriteLine($"Work factor for Validate and Replace Password (with equal work factor): {hashInfoForEqualWorkFactor.WorkFactor}");
Console.WriteLine($"Work factor for Validate and Replace Password (with higher work factor): {hashInfoForHigherWorkFactor.WorkFactor}");

string newPasswordForValidateAndReplaceWithLowerWorkFactorAndForceWorkFactor = BCrypt.Net.BCrypt.ValidateAndReplacePassword("password", currentHash: passwordHash1, "newPassword", workFactor: 10, forceWorkFactor: true);
BCrypt.Net.HashInformation? hashInfoForLowerWorkFactorAndForceWorkFactor = BCrypt.Net.BCrypt.InterrogateHash(newPasswordForValidateAndReplaceWithLowerWorkFactorAndForceWorkFactor);
Console.WriteLine($"New password for Validate and Replace Password (with lower work factor and force Work factor = true): {newPasswordForValidateAndReplaceWithLowerWorkFactorAndForceWorkFactor}");
Console.WriteLine($"Work factor for Validate and Replace Password (with lower work factor and force Work factor = true): {hashInfoForLowerWorkFactorAndForceWorkFactor.WorkFactor}\n\n");

Console.ReadKey();
