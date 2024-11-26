function openPaymentModal(plan, amount) {
    document.getElementById("paymentModal").style.display = "block";
    document.getElementById("paymentForm").onsubmit = function() {
        processPayment(plan, amount);
        return false; 
    };
}

function closePaymentModal() {
    document.getElementById("paymentModal").style.display = "none";
}

function processPayment(plan, amount) {
    const cardNumber = document.getElementById("cardNumber").value;
    const expiryDate = document.getElementById("expiryDate").value;
    const cvc = document.getElementById("cvc").value;

    alert(`Payment of ${amount} грн for ${plan} using card ${cardNumber} is successful!`);

    closePaymentModal();
}

document.getElementById('cardNumber').addEventListener('input', function (e) {
    let value = e.target.value.replace(/\D/g, ''); 
    value = value.substring(0, 16); 

    let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
    
    e.target.value = formattedValue; 
});

