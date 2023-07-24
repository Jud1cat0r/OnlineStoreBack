using AuthAPI.Context;
using AuthAPI.Helpers;
using AuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext) 
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<ActionResult> AuthenticateAsync([FromBody] User userObj) 
        {
            if (userObj == null)
                return BadRequest();
            //проверка на login
            var user = await _authContext.Users.FirstOrDefaultAsync(c => c.UserName == userObj.UserName);
            if (user == null)
                return NotFound(new { Message = "User Not Found!" });
            //проверка на пароль
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                return BadRequest(new
                {
                    Message = "Password is incorrect"
                });

            user.Token = CreateJwt(user);

            return Ok(new
            {
                Token = user.Token,
                Message = "Login Success!"
            });
        }



        [HttpPost("register")]
        public async Task<ActionResult> RegisterAsync([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            if(await CheckUserNameAsync(userObj.UserName))
                return BadRequest(new
                {
                    Message = "Username already exist"
                });
            
            if (await CheckEmailAsync(userObj.Email))
                return BadRequest(new
                {
                    Message = "Email already exist"
                });

            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new
                { 
                    Message = pass.ToString()
                });


            //шифрование пароля
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);

            userObj.Role = "User";
            userObj.Token = "";

            //если все успешно, добавляем пользователя в БД
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message = "User Registered!"
            });
        }

        //проверка на уникальность username
        private Task<bool> CheckUserNameAsync(string userName)
            => _authContext.Users.AnyAsync(c => c.UserName == userName);

        //проверка на уникальность email
        private Task<bool> CheckEmailAsync(string email)
            => _authContext.Users.AnyAsync(c => c.Email == email);

        //проверка пороля на сложность
        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if(!Regex.IsMatch(password, "[a-z]") 
                && !Regex.IsMatch(password, "[A-Z]") 
                && !Regex.IsMatch(password, "[0-9]"))
                sb.Append("Password should be Alphanumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,=,-,{,},\\[,\\],?,:,;,|,',\\,.,/,`,~]"))
                sb.Append("Password should contain special chars" + Environment.NewLine);
            return sb.ToString();
        }

        // создание jwt token 
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("secretkey....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, user.FirstName)
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,//информация
                Expires = DateTime.Now.AddDays(1),//время действия токена
                SigningCredentials = credentials//ключ
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }
    }
}
