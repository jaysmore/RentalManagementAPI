//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace RentalManagementAPI.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class Invoice
    {
        public int invoiceID { get; set; }
        public Nullable<int> invoiceNum { get; set; }
        public Nullable<int> jobID { get; set; }
        public Nullable<int> rentalID { get; set; }
        public Nullable<int> amount { get; set; }
        public Nullable<int> equipmentID { get; set; }
        public Nullable<int> vendorID { get; set; }
    
        public virtual Equipment Equipment { get; set; }
        public virtual Job Job { get; set; }
        public virtual Rental Rental { get; set; }
        public virtual Vendor Vendor { get; set; }
    }
}
