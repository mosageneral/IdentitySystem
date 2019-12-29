////////////////////////////// Script Runs  At The Pages Load//////////////////////////////////// 
$(function () {

 ///////////////////////////////////Edit User Page ////////////////////////////////////////////////////

    var ShowDiv = $("#ChangePasswordDiv");
    ShowDiv.hide();


});

//////////////////////////////////////////////////////////////////////////////////////////////////


/////////////Confirm Password Script In Register Page In The Account Controller/////////////////////////////

var Password = $("#Password").val(); //User Password Input ID 

var ConfirmPassword = $("#ConfirmPassword").val(); //User Confirm Password Input

var BtnRegister = $("#btnRigster"); //Btn Register That Post The Form

BtnRegister.click(function (event) {
    debugger;
  //Check If The Password Not Match Then Prevent The Action 
    if (Password != ConfirmPassword) {
        event.preventDefault();
        Password = "";
        ConfirmPassword = "";
        alert("Password Not Matches");
    }

});
/////////////Confirm Password Script In Edit Page In The Account Controller/////////////////////////////




var BtnRegisteredit = $("#editbtnSubmit"); //Btn Edit That Post The Form

BtnRegisteredit.click(function (event) {
    debugger;
    var Passwordedit = $("#editPassword").val(); //User Password Input ID 

    var ConfirmPasswordedit = $("#editConfirmPassword").val(); //User Confirm Password Input

    //Check If The Password Not Match Then Prevent The Action 
    if (Passwordedit != ConfirmPasswordedit ) {
        event.preventDefault();
        Passwordedit = "";
        ConfirmPasswordedit = "";
        alert("Password Not Matches");
    }

});
//Script To Toggle The Password Div 
$("#ChangePasswordBtn").click(function () {
    debugger;
    var ShowDiv = $("#ChangePasswordDiv");
    ShowDiv.toggle("slow");
});