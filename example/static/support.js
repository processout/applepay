/*
 Copyright (C) 2016 Apple Inc. All Rights Reserved.
 See LICENSE.txt for this sample’s licensing information

 Abstract:
 The main client-side JS. Handles displaying the Apple Pay button and requesting a payment.
 */

/**
 * This method is called when the page is loaded.
 * We use it to show the Apple Pay button as appropriate.
 * Here we're using the ApplePaySession.canMakePayments() method,
 * which performs a basic hardware check.
 *
 * If we wanted more fine-grained control, we could use
 * ApplePaySession.canMakePaymentsWithActiveCards() instead.
 */
document.addEventListener('DOMContentLoaded', function() {
    if (window.ApplePaySession) {
        if (ApplePaySession.canMakePayments) {
            showApplePayButton();
        }
    }
});

function showApplePayButton() {
    HTMLCollection.prototype[Symbol.iterator] = Array.prototype[Symbol.iterator];
    const buttons = document.getElementsByClassName("apple-pay-button");
    for (let button of buttons) {
        button.className += " visible";
    }
}


/**
 * Apple Pay Logic
 * Our entry point for Apple Pay interactions.
 * Triggered when the Apple Pay button is pressed
 */
function applePayButtonClicked() {
    const paymentRequest = {
        countryCode: 'FR',
        currencyCode: 'EUR',
        shippingMethods: [
            {
                label: 'Free Shipping',
                amount: '0.00',
                identifier: 'free',
                detail: 'Delivers in five business days',
            },
            {
                label: 'Express Shipping',
                amount: '0.49',
                identifier: 'express',
                detail: 'Delivers in two business days',
            },
        ],

        lineItems: [
            {
                label: 'Shipping',
                amount: '0.00',
            }
        ],

        total: {
            label: 'Apple Pay Example',
            amount: '0.01',
        },

        supportedNetworks:[ 'amex', 'discover', 'masterCard', 'visa'],
        merchantCapabilities: [ 'supports3DS' ],

        requiredShippingContactFields: [ 'email' ],
    };

    const session = new ApplePaySession(1, paymentRequest);

    /**
     * Merchant Validation
     * We call our merchant session endpoint, passing the URL to use
     */
    session.onvalidatemerchant = (event) => {
        console.log("Validate merchant");
        const validationURL = event.validationURL;
        getApplePaySession(event.validationURL).then(function(response) {
            console.log(response);
            session.completeMerchantValidation(response);
        });
    };

    /**
     * Shipping Method Selection
     * If the user changes their chosen shipping method we need to recalculate
     * the total price. We can use the shipping method identifier to determine
     * which method was selected.
     */
    session.onshippingmethodselected = (event) => {
        const shippingCost = event.shippingMethod.identifier === 'free' ? '0.00' : '0.49';
        const totalCost = event.shippingMethod.identifier === 'free' ? '0.01' : '0.50';

        const lineItems = [
            {
                label: 'Shipping',
                amount: shippingCost,
            },
        ];

        const total = {
            label: 'Apple Pay Example',
            amount: totalCost,
        };

        session.completeShippingMethodSelection(ApplePaySession.STATUS_SUCCESS, total, lineItems);
    };

    /**
     * Payment Authorization
     * Here you receive the encrypted payment data. You would then send it
     * on to your payment provider for processing, and return an appropriate
     * status in session.completePayment()
     */
    session.onpaymentauthorized = (event) => {
        // Send payment for processing...
        const payment = event.payment;
        console.log(payment);
        var r = new XMLHttpRequest();
        r.open("POST", "/processApplePayResponse");
        r.onreadystatechange = function() {
            if (r.readyState != 4) {
                return;
            }
            if (r.status != 200) {
                session.completePayment(ApplePaySession.STATUS_FAILURE);
            }
            session.completePayment(ApplePaySession.STATUS_SUCCESS);
        }
        r.setRequestHeader("Content-Type", "application/json");
        r.send(JSON.stringify(payment));
    }

    // All our handlers are setup - start the Apple Pay payment
    session.begin();
}