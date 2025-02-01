using JwtAuthApp.Core.Entities;
using JwtAuthApp.Core.Interfaces;
using JwtAuthApp.Core.Models;
using JwtAuthApp.Infra;
using JwtAuthApp.Infra.Services;
using JwtAuthApp.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// **1. Configure Services**
// Add DbContext for Entity Framework Core with SQL Server configuration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection"))
);

// Configure Identity for user and role management
builder.Services.AddIdentity<User, Role>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders(); // Adds support for generating and validating tokens

// Add controllers
builder.Services.AddControllers();

// Add API documentation tools
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// **2. Configure JWT Authentication**
// Read JWT settings from app configuration
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(jwtSettings["SecretKey"])
        )
    };
});

// Bind JWT settings to a strongly-typed configuration object
builder.Services.Configure<JwtSettings>(jwtSettings);

// Register the token service for DI
builder.Services.AddScoped<ITokenService, TokenService>();

var app = builder.Build();

// **3. Seed Data on Application Startup**
using (var scope = app.Services.CreateScope())
{
    await SeedData.Initialize(scope.ServiceProvider);
}

// **4. Configure Middleware**
// Enable Swagger UI in development environment
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Enable HTTPS redirection
app.UseHttpsRedirection();

// Enable JWT authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

// Map controllers to endpoints
app.MapControllers();

// Run the application
app.Run();