using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Models.IdentityModels
{
    //This Is A View Model For The User Account To Register With
  public  class RegisterUser
    {
        [Required]
    
        public string UserName { get; set; }
        [Required]
        
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
